#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore { // 세마포어
	unsigned value;             /* Current value. */
	struct list waiters;        /* List of waiting threads. */
};

void sema_init (struct semaphore *, unsigned value); //sema 초깃값으로 초기회
void sema_down (struct semaphore *); //"down" 연산을 sema에 실행, sema 값이 양수가 될 때까지 기다렸다가 양수가 되면 -1
bool sema_try_down (struct semaphore *); //sema "down" 연산을 기다리지 않고 시도
void sema_up (struct semaphore *); // sema 값을 증가시키는 "up" 연산 실행, 기다리는 쓰레드가 있다면 그들 중 하나를 깨움
void sema_self_test (void);

/* Lock. */
struct lock { //락
	struct thread *holder;      /* Thread holding lock (for debugging). */
	struct semaphore semaphore; /* Binary semaphore controlling access. */
};


void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);
void reset_priority(void);


/* Condition variable. */
struct condition { //컨디션
	struct list waiters;        /* List of waiting threads. */
};

void cond_init (struct condition *); //condition 초기화
void cond_wait (struct condition *, struct lock *); //원자적으로 lock(모니터락)을 놓아주고 컨디션 변수 cond가 다른 코드로부터 신호받는 걸 기다림, 신호 받으면 return 전에 lock 다시 획득
void cond_signal (struct condition *, struct lock *); //cond를 기다리는 쓰레드가 있다면(cond는 모니터락으로 보호), 기다리는 쓰레드 중 하나를 깨움
void cond_broadcast (struct condition *, struct lock *); //cond를 기다리는 쓰레드가 있다면(cond는 모니터락으로 보호), 모든 쓰레드를 깨움


bool
cmp_sema_priority(const struct list_elem *, const struct list_elem *, void *);

/* Optimization barrier.
 *
 * The compiler will not reorder operations across an
 * optimization barrier.  See "Optimization Barriers" in the
 * reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */
