
typedef struct {
    char unused; // TODO
} Mutex;

int mutex_init(Mutex *mutex);
int mutex_free(Mutex *mutex);
int mutex_lock(Mutex *mutex);
int mutex_unlock(Mutex *mutex);
