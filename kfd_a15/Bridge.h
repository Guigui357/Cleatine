// language: C, file: kfd_a15/Bridge.h, target: arm64e app
#ifndef BRIDGE_H
#define BRIDGE_H
#include <stdint.h>

int      kfd_a15(void);
uint32_t kfd_a15_read_uid(void);
int      bootstrap_main(void);

int kfd_a15_run(void);
int install_bootstrap(void);

#endif
