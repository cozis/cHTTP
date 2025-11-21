
#ifdef _WIN32
typedef CRITICAL_SECTION Mutex;
#else
typedef pthread_mutex_t Mutex;
#endif

int mutex_init(Mutex *mutex);
int mutex_free(Mutex *mutex);
int mutex_lock(Mutex *mutex);
int mutex_unlock(Mutex *mutex);
