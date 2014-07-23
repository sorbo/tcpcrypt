#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "profile.h"

#define MAX_SAMPLES	128

struct samples {
	char		*s_desc;
	union {
		struct timeval	s_tv;
		uint64_t	s_tsc;
	} u;
};

static struct state {
	struct samples	s_time[MAX_SAMPLES];
	int		s_timec;
        struct timeval  s_speed_a;
        struct timeval  s_speed_b;
        unsigned int    s_speed_num;
	unsigned int	s_speed_avg;
	int		s_speed_avgc;
        speed_cb        s_speed_cb;
	int		s_discard;
	unsigned int	s_sum;
	unsigned int	s_samples;
	int		s_enable;
	int		s_time_source;
} _state;

int time_diff(struct timeval *a, struct timeval *now)
{       
        int diff = 0;
        int neg = 1;

        if ((a->tv_sec > now->tv_sec)
            || (a->tv_sec == now->tv_sec && a->tv_usec > now->tv_usec)) {
                struct timeval *tmp = a;
                
                a   = now;
                now = tmp;
                neg = -1;
        }
        
        diff = now->tv_sec - a->tv_sec;

        if (diff == 0)
                diff = now->tv_usec - a->tv_usec;
        else {  
                diff--;
                diff *= 1000 * 1000;
                diff += 1000 * 1000 - a->tv_usec;
                diff += now->tv_usec;
        }
        
        assert(diff >= 0);

        return diff * neg;
}

static inline uint64_t do_get_tsc(void)
{       
        uint64_t t = 0;

#if defined(__amd64__) || defined(__i386__)
        __asm__ volatile (".byte 0x0f, 0x31" : "=A" (t));
#else
	abort();
#endif

        return t;
}

uint64_t get_tsc(void)
{
	return do_get_tsc();
}

void profile_add(int verb, char *desc)
{
	if (_state.s_enable < verb)
		return;

	assert(_state.s_timec < MAX_SAMPLES);

	_state.s_time[_state.s_timec].s_desc = desc;

	switch (_state.s_time_source) {
	case TIME_SOURCE_GETTIMEOFDAY:
		gettimeofday(&_state.s_time[_state.s_timec].u.s_tv, NULL);
		break;
	
	case TIME_SOURCE_TSC:
		_state.s_time[_state.s_timec].u.s_tsc = do_get_tsc();
		break;

	default:
		assert(!"Unknown time source");
		break;
	}

	_state.s_timec++;
}

static unsigned int sample_diff(struct samples *a, struct samples *b)
{
	uint64_t tsc_diff;
	unsigned int x;

	switch (_state.s_time_source) {
	case TIME_SOURCE_GETTIMEOFDAY:
		return time_diff(&a->u.s_tv, &b->u.s_tv);

	case TIME_SOURCE_TSC:
		tsc_diff = b->u.s_tsc - a->u.s_tsc;
		assert(tsc_diff >= 0);

		x = (unsigned int) tsc_diff;
		assert(((uint64_t) x) == tsc_diff);
		return x;

	default:
		assert(!"Unknown time source");
		break;
	}

	return -1;
}

static const char *sample_unit(void)
{
	static const char *gt  = "s.us";
	static const char *tsc = "cycles";

	switch (_state.s_time_source) {
	case TIME_SOURCE_GETTIMEOFDAY:
		return gt;

	case TIME_SOURCE_TSC:
		return tsc;

	default:
		assert(!"Unknown time source");
		break;
	}

	return NULL;
}

static const char *sample_str(struct samples *s)
{
	static char buf[1024];

	switch (_state.s_time_source) {
	case TIME_SOURCE_GETTIMEOFDAY:
		sprintf(buf, "%u.%u",
			(unsigned int) s->u.s_tv.tv_sec,
			(unsigned int) s->u.s_tv.tv_usec);
		break;

	case TIME_SOURCE_TSC:
		sprintf(buf, "%llu", s->u.s_tsc);
		break;

	default:
		assert(!"Unknown time source");
		break;
	}

	return buf;
}

static void print_time(void)
{
	unsigned int total;
	struct samples *s = _state.s_time;
	unsigned int diff;
	float pc;

	total = sample_diff(&_state.s_time[0],
			    &_state.s_time[_state.s_timec - 1]);

	printf("Time (%s)\t\t      diff\t   %%\tdesc\n", sample_unit());

	while (_state.s_timec--) {
		if (s != _state.s_time)
			diff = sample_diff((s - 1), s);
		else
			diff = 0;

		pc = (float) diff / (float) total * 100.0;

		printf("%-20s\t%10u\t%4.1f\t%s\n",
		       sample_str(s),
		       diff,
		       pc,
		       s->s_desc);

		s++;
	}

	printf("Total time %u\n", total);

	_state.s_timec = 0;
}

void profile_print(void)
{
	if (!_state.s_enable)
		return;

	if (_state.s_timec)
		print_time();
}

void speed_start(speed_cb cb)
{       
        _state.s_speed_cb = cb;
        gettimeofday(&_state.s_speed_a, NULL);
}

void sample_add(unsigned int sample)
{       
        unsigned int old = _state.s_sum;

        if (_state.s_discard != 0) {
                _state.s_discard--;
                return;
        }
        
        _state.s_sum += sample;
        _state.s_samples++;

        assert(_state.s_sum >= old);
        assert(_state.s_samples);
}

void speed_add(unsigned int sample)
{           
        unsigned int old = _state.s_speed_num;
        unsigned int diff;
        unsigned int rate;
        float speed;
	unsigned int avg = 0;

        gettimeofday(&_state.s_speed_b, NULL);

        _state.s_speed_num += sample;
        assert(_state.s_speed_num >= old);

        diff = time_diff(&_state.s_speed_a, &_state.s_speed_b);

        if (diff < 1000 * 1000)
                return;

        speed = (float) _state.s_speed_num / (float) diff;

	if (_state.s_speed_avgc >= 5) {
		avg = (double) _state.s_speed_avg 
		      / (double) _state.s_speed_avgc;

		_state.s_speed_avg  = 0;
		_state.s_speed_avgc = 0;
	}

        rate  = _state.s_speed_cb(speed, avg);
        sample_add(rate);

	old = _state.s_speed_avg;
	_state.s_speed_avg += rate;
	assert(_state.s_speed_avg >= old);
	_state.s_speed_avgc++;

        _state.s_speed_a   = _state.s_speed_b;
        _state.s_speed_num = 0;
}

static void print_average(void)
{       
        printf("%u samples, average %u\n",
               _state.s_samples, _state.s_sum / _state.s_samples);
}

void profile_end(void)
{
	if (_state.s_samples)
		print_average();
}

void profile_setopt(int opt, int val)
{
	switch (opt) {
	case PROFILE_DISCARD:
		_state.s_discard = val;
		break;

	case PROFILE_ENABLE:
		_state.s_enable = val;
		break;

	case PROFILE_TIME_SOURCE:
		_state.s_time_source = val;
		break;

	default:
		abort();
	}
}
