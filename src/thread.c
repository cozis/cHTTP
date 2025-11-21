
int mutex_init(Mutex *mutex)
{
#ifdef _WIN32
    InitializeCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_init(mutex, NULL)) // TODO: mock
        return -1;
    return 0;
#endif
}

int mutex_free(Mutex *mutex)
{
#ifdef _WIN32
    DeleteCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_destroy(mutex)) // TODO: mock
        return -1;
    return 0;
#endif
}

int mutex_lock(Mutex *mutex)
{
#ifdef _WIN32
    EnterCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_lock(mutex)) // TODO: mock
        return -1;
    return 0;
#endif
}

int mutex_unlock(Mutex *mutex)
{
#ifdef _WIN32
    LeaveCriticalSection(mutex); // TODO: mock?
    return 0;
#else
    if (pthread_mutex_unlock(mutex)) // TODO: mock
        return -1;
    return 0;
#endif
}
