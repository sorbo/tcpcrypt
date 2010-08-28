#ifndef __TCPCRYPT_PROFILE_H__
#define __TCPCRYPT_PROFILE_H__

typedef unsigned int (*speed_cb)(float sample, unsigned int curavg);

enum {
	PROFILE_DISCARD			= 1,
	PROFILE_ENABLE,
	PROFILE_TIME_SOURCE,
};

enum {
	TIME_SOURCE_TSC			= 0,
	TIME_SOURCE_GETTIMEOFDAY,
};

extern void	speed_start(speed_cb cb);
extern void	speed_add(unsigned int sample);
extern void	profile_print(void);
extern void	profile_add(int verb, char *desc);
extern void	sample_add(unsigned int sample);
extern void	profile_end(void);
extern void	profile_setopt(int opt, int val);
extern int      time_diff(struct timeval *past, struct timeval *now);
extern uint64_t get_tsc(void);

#endif /* __TCPCRYPT_PROFILE_H__ */
