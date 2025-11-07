#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* 8254 타이머 칩의 하드웨어 세부사항은 [8254]를 참조. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* OS가 부팅된 이후의 타이머 틱 수. */
static int64_t ticks;

/* 타이머 틱당 루프 수.
   timer_calibrate()에 의해 초기화됨. */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* 8254 프로그래머블 인터벌 타이머(PIT)를 초당 PIT_FREQ번
   인터럽트하도록 설정하고, 해당 인터럽트를 등록. */
void
timer_init (void) {
	/* 8254 입력 주파수를 TIMER_FREQ로 나누고,
	   가장 가까운 값으로 반올림. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: 카운터 0, LSB 다음 MSB, 모드 2, 바이너리. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* 짧은 지연을 구현하는 데 사용되는 loops_per_tick을 조정. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* loops_per_tick을 타이머 틱 하나보다 여전히 작은
	   가장 큰 2의 거듭제곱으로 근사. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* loops_per_tick의 다음 8비트를 정제. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* OS가 부팅된 이후의 타이머 틱 수를 반환. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	int64_t t = ticks;
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* THEN 이후 경과한 타이머 틱 수를 반환. THEN은
   timer_ticks()에 의해 한 번 반환된 값이어야 함. */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

/* 약 TICKS 타이머 틱 동안 실행을 일시 중단. */
void
timer_sleep (int64_t ticks) {
	int64_t start = timer_ticks ();

	ASSERT (intr_get_level () == INTR_ON);
	
	thread_sleep(start + ticks);
	// while (timer_elapsed (start) < ticks)
	// 	thread_yield ();
}

/* 약 MS 밀리초 동안 실행을 일시 중단. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* 약 US 마이크로초 동안 실행을 일시 중단. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* 약 NS 나노초 동안 실행을 일시 중단. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* 타이머 통계를 출력. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* 타이머 인터럽트 핸들러. */
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;
	thread_tick ();
	thread_awake(ticks);
}

/* LOOPS 반복이 하나 이상의 타이머 틱을 기다리면 true를 반환,
   그렇지 않으면 false를 반환. */
static bool
too_many_loops (unsigned loops) {
	/* 타이머 틱을 기다림. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* LOOPS 루프 실행. */
	start = ticks;
	busy_wait (loops);

	/* 틱 카운트가 변경되었다면, 반복이 너무 오래 걸린 것임. */
	barrier ();
	return start != ticks;
}

/* 짧은 지연을 구현하기 위해 단순 루프를 LOOPS번 반복.

   코드 정렬이 타이밍에 상당한 영향을 미칠 수 있으므로,
   이 함수가 다른 위치에서 다르게 인라인되면 결과를 예측하기
   어려워지기 때문에 NO_INLINE으로 표시됨. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* 약 NUM/DENOM 초 동안 대기. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* NUM/DENOM 초를 타이머 틱으로 변환, 내림.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* 최소 하나 이상의 완전한 타이머 틱을 기다림. CPU를
		   다른 프로세스에 양보하므로 timer_sleep()을 사용함. */
		timer_sleep (ticks);
	} else {
		/* 그렇지 않으면, 더 정확한 서브-틱 타이밍을 위해
		   busy-wait 루프를 사용. 오버플로우 가능성을 피하기 위해
		   분자와 분모를 1000으로 축소함. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}
