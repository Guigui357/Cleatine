// language: Objective-C, file: kfd_a15/Bridge.m, target: arm64e
#import "Bridge.h"
#include <unistd.h>

int kfd_a15_run(void) { return kfd_a15(); }

uint32_t kfd_a15_read_uid(void) { return (uint32_t)getuid(); }

int install_bootstrap(void) { return bootstrap_main(); }
