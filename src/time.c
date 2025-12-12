
Time get_current_time(void)
{
#ifdef _WIN32
    {
        int64_t count;
        int64_t freq;
        int ok;

        ok = QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        uint64_t res = 1000 * (double) count / freq;
        return res;
    }
#else
    {
        struct timespec time;

        if (clock_gettime(CLOCK_REALTIME, &time))
            return INVALID_TIME;

        uint64_t res;

        uint64_t sec = time.tv_sec;
        if (sec > UINT64_MAX / 1000)
            return INVALID_TIME;
        res = sec * 1000;

        uint64_t nsec = time.tv_nsec;
        if (res > UINT64_MAX - nsec / 1000000)
            return INVALID_TIME;
        res += nsec / 1000000;

        return res;
    }
#endif
}