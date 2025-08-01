#include "time-and-json.h"


int64_t get_milliseconds_timestamp()
{
	struct timeval tv;
	gettimeofday(&tv, 0);
	return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int write_to_json()