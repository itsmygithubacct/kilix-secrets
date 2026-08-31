/* H0 Argon2id calibration for decision 7's production point.
 *
 * Runs as PID 1 in a minimal initramfs so the measurement sees the H0 capacity
 * envelope and nothing else. Build and run:
 *
 *   cc -O2 -std=c11 -static -o init tools/h0-calibrate.c -lsodium -lpthread
 *   ( mkdir -p r/proc && cp init r/init && cd r && find . | cpio -o -H newc | gzip > ../ir.gz )
 *   qemu-system-x86_64 -enable-kvm -machine q35 -cpu qemu64 -smp 2 -m 4096 \
 *     -kernel /boot/vmlinuz-$(uname -r) -initrd ir.gz \
 *     -append "console=ttyS0 quiet panic=1" -display none -nographic -no-reboot
 *
 * -enable-kvm is REQUIRED and is not optional tuning: under TCG the same corner
 * measures ~9.4x slower, which measures the emulator rather than the tier.
 * -cpu qemu64 is deliberate -- it pins the guest ISA so libsodium selects the
 * same Argon2id implementation on any build host.
 *
 * Corrected method per root's 2026-08-25 note:
 * warm-up discarded explicitly; a distribution rather than a median of three;
 * MAX and p95 reported because the ceiling is what matters; monotonicity in
 * opslimit at fixed memlimit checked as a harness correctness test. */
#define _GNU_SOURCE
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

#define WARMUP 3
#define TRIALS 15

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static double ms_now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}
static void loadavg(const char *tag) {
    char buf[128] = {0}; FILE *f = fopen("/proc/loadavg", "r");
    if (f) { if (fgets(buf, sizeof buf, f)) { buf[strcspn(buf, "\n")] = 0; } fclose(f); }
    printf("LOADAVG %s: %s\n", tag, buf[0] ? buf : "(unavailable)");
}

int main(void) {
    static const unsigned long long OPS[] = {3, 4, 5, 6};
    static const size_t MEM_MIB[] = {256, 384, 512};
    unsigned char key[32];
    const char *pw = "h0-calibration-fixture-passphrase-not-a-credential";
    unsigned char salt[crypto_pwhash_SALTBYTES];

    mount("proc", "/proc", "proc", 0, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== H0 ARGON2ID CALIBRATION (corrected method) ===\n");
    if (sodium_init() < 0) { printf("FATAL sodium_init\n"); goto done; }
    memset(salt, 0x5a, sizeof salt);
    printf("libsodium %s | warm-up discarded %d | measured trials %d\n",
           sodium_version_string(), WARMUP, TRIALS);
    loadavg("START");

    for (size_t m = 0; m < sizeof MEM_MIB / sizeof *MEM_MIB; m++) {
        double prev_med = -1.0; int mono = 1;
        size_t memlimit = MEM_MIB[m] * 1024UL * 1024UL;
        for (size_t o = 0; o < sizeof OPS / sizeof *OPS; o++) {
            double s[TRIALS]; double t0, t1;
            for (int i = 0; i < WARMUP; i++) {
                if (crypto_pwhash(key, sizeof key, pw, strlen(pw), salt,
                        OPS[o], memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
                    printf("FATAL pwhash ops=%llu mem=%zuMiB\n", OPS[o], MEM_MIB[m]); goto done; }
            }
            for (int i = 0; i < TRIALS; i++) {
                t0 = ms_now();
                if (crypto_pwhash(key, sizeof key, pw, strlen(pw), salt,
                        OPS[o], memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
                    printf("FATAL pwhash\n"); goto done; }
                t1 = ms_now(); s[i] = t1 - t0;
            }
            qsort(s, TRIALS, sizeof s[0], cmp_d);
            double med = s[TRIALS / 2];
            double p95 = s[(int)(0.95 * (TRIALS - 1))];
            printf("POINT ops=%llu mem=%zuMiB min=%.1f med=%.1f p95=%.1f MAX=%.1f spread=%.2fx\n",
                   OPS[o], MEM_MIB[m], s[0], med, p95, s[TRIALS - 1], s[TRIALS - 1] / s[0]);
            if (prev_med >= 0.0 && med < prev_med) mono = 0;
            prev_med = med;
        }
        printf("MONOTONIC mem=%zuMiB: %s\n", MEM_MIB[m], mono ? "yes (harness sound)" : "NO -- HARNESS SUSPECT, numbers unusable");
    }
    loadavg("END");
    printf("=== CALIBRATION COMPLETE ===\n");
done:
    sync();
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    for (;;) pause();
}
