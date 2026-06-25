/*
 * TEST 3: Multi-Threaded Race Condition (CFI + per-thread shadow stack)
 * =======================================================================
 * Fix over original:
 *   • Use pthread_barrier for deterministic synchronisation instead of
 *     volatile spin-flags, which had a race letting tid=2 (attacker)
 *     execute the indirect call instead of tid=1 (worker).
 *   • thread_attacker does ONLY data writes — no function calls —
 *     so it never appears in CFI or shadow-stack events.
 *   • The indirect call that triggers the CFI violation is therefore
 *     always in thread_worker (tid=1), matching the expected log.
 *
 * Compile:
 *   gcc -fno-stack-protector -no-pie -g -pthread -o vuln_thread vuln_thread.c
 *
 * Run:
 *   pin -t obj-intel64/MyPinTool.so -- ./vuln_thread
 *
 * Expected output (cfi_shadow.log):
 *   [IMAGE] Main exe: ...
 *   [THREAD START] tid=0
 *   [CFI PROFILE] tid=0 call #1 target=0x<legitimate_work> (legitimate_work)
 *   [CFI PROFILE] tid=0 call #2 ...
 *   [CFI PROFILE] tid=0 call #3 ...
 *   [CFI PROFILE] tid=0 call #4 ...
 *   [CFI PROFILE] tid=0 call #5 ...
 *   [CFI] Profile done. 1 targets recorded. Enforcing now.
 *   [THREAD START] tid=1
 *   [THREAD START] tid=2
 *   [CFI VIOLATION] tid=1
 *     Target   : 0x<evil_work>
 *     Callsite : 0x<...>
 *     Symbol   : evil_work
 *   [THREAD END] tid=1
 *   [THREAD END] tid=2
 *   [THREAD END] tid=0
 *
 *   ========== SUMMARY ==========
 *   Shadow Stack Violations : 0
 *   CFI Violations          : 1
 *   CFI observed targets    : 1
 *   Exit code               : 0
 *   ==============================
 */

#include <stdio.h>
#include <pthread.h>

typedef void (*work_fn_t)(void);

/*
 * barrier_a : both threads reach it once they are ready.
 *             After it: attacker overwrites the callback.
 * barrier_b : both threads reach it after the overwrite.
 *             After it: worker calls the (now-evil) callback.
 */
static pthread_barrier_t barrier_a;
static pthread_barrier_t barrier_b;

volatile work_fn_t shared_callback = NULL;

void legitimate_work(void) { printf("[*] legitimate_work\n"); }
void evil_work(void)       { printf("[!!!] evil_work — callback hijacked\n"); }

/* ── Worker thread (tid=1) ──────────────────────────────────── */
void *thread_worker(void *arg)
{
    /* Step 1: set the callback to the legitimate target */
    shared_callback = legitimate_work;

    /* Step 2: signal attacker we are ready, then wait for overwrite */
    pthread_barrier_wait(&barrier_a);   /* attacker will overwrite here */
    pthread_barrier_wait(&barrier_b);   /* overwrite is done            */

    /* Step 3: indirect call — shared_callback now points to evil_work */
    shared_callback();                  /* CFI VIOLATION expected here  */
    return NULL;
}

/* ── Attacker thread (tid=2) ────────────────────────────────── */
void *thread_attacker(void *arg)
{
    /* Wait until worker has set the legitimate callback */
    pthread_barrier_wait(&barrier_a);

    /* Overwrite — pure data write, no function call */
    shared_callback = evil_work;

    /* Signal worker to proceed */
    pthread_barrier_wait(&barrier_b);
    return NULL;
}

/* ── Main ───────────────────────────────────────────────────── */
int main(void)
{
    /* 5 legitimate indirect calls → push tool into enforce mode */
    work_fn_t fn = legitimate_work;
    fn(); fn(); fn(); fn(); fn();
    /* evil_work is NOT in observedTargets — enforce mode is now ON */

    pthread_barrier_init(&barrier_a, NULL, 2);
    pthread_barrier_init(&barrier_b, NULL, 2);

    pthread_t t_worker, t_attacker;
    pthread_create(&t_worker,   NULL, thread_worker,   NULL);
    pthread_create(&t_attacker, NULL, thread_attacker, NULL);
    pthread_join(t_worker,   NULL);
    pthread_join(t_attacker, NULL);

    pthread_barrier_destroy(&barrier_a);
    pthread_barrier_destroy(&barrier_b);
    return 0;
}
