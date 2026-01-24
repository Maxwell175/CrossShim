// Minimal ARM64 stub for QEMU initialization
// This binary is loaded by QEMU and just exits immediately.
// We override libafl_qemu_main() to prevent this from running,
// then set PC to our own code after QEMU initializes.

.global _start

.section .text
_start:
    // Exit syscall (in case we ever run)
    // mov x0, #0      // exit code
    // mov x8, #93     // sys_exit
    // svc #0

    // Infinite loop - we should never reach here because
    // libafl_qemu_main() is overridden to return immediately
.loop:
    b .loop
