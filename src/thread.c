
int mutex_init(Mutex *mutex)
{
#ifdef _WIN32
    InitializeCriticalSection(mutex);
    return 0;
#else
    if (pthread_mutex_init(mutex, NULL))
        return -1;
    return 0;
#endif
}

int mutex_free(Mutex *mutex)
{
#ifdef _WIN32
    DeleteCriticalSection(mutex);
    return 0;
#else
    if (pthread_mutex_destroy(mutex))
        return -1;
    return 0;
#endif
}

int mutex_lock(Mutex *mutex)
{
#ifdef _WIN32
    EnterCriticalSection(mutex);
    return 0;
#else
    if (pthread_mutex_lock(mutex))
        return -1;
    return 0;
#endif
}

int mutex_unlock(Mutex *mutex)
{
#ifdef _WIN32
    LeaveCriticalSection(mutex);
    return 0;
#else
    if (pthread_mutex_unlock(mutex))
        return -1;
    return 0;
#endif
}
