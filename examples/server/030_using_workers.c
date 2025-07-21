#include <stdlib.h>
#include <stdbool.h>
#include <chttp.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef void*              Thread;
typedef unsigned long      ThreadReturn;
typedef CRITICAL_SECTION   Mutex;
typedef CONDITION_VARIABLE Condvar;
#endif

#ifdef __linux__
#include <pthread.h>
typedef pthread_t          Thread;
typedef void*              ThreadReturn;
typedef pthread_mutex_t    Mutex;
typedef pthread_cond_t     Condvar;
#endif

// NOTE: This example doesn't work yet!

// This example shows how to delegate the response creation
// process to other threads.
//
// Your server may have some endpoints that require considerable
// computation or may be waiting for some external system to
// complete. If we used the current pattern we've been using for
// generating requests, following request will have to wait until
// this processing has concluded.
//
// One solution for this situation is to create a separate thread
// to do the waiting or processing. When a request is received
// that requires processing, it is passed to the second thread.
// In the mean time, the main thread can process the next request.
// When the thread has finished, it can just call the usual
// functions to produce a response.

// The following types are used to describe a job the worker
// needs to work on.
typedef enum {

    // Special value used to tell the worker the program is terminating
    NO_JOB,

    // We assume jobs may be of two different types we call A and B
    JOB_A,
    JOB_B,

} JobType;

typedef struct {
    JobType type;
    HTTP_ResponseBuilder builder;
} Job;

// Maximum number of jobs that can be buffered at once
#define MAX_JOBS 100

void init_job_queue(void);
void free_job_queue(void);

// This function pops an item from the job queue. If the
// queue is empty, the thread will block until one is
// available.
Job pop_job(void);

// This function adds a job to the queue. The block argument
// changes the behavior when the queue is full and there is
// no space for a new job. If the block argument is true and
// there is no space, the thread waits. If the argument is
// false the function exits immediately by returning false
// with no new job pushed.
bool push_job(Job job, bool block);

void thread_create(Thread *thread, void *arg, ThreadReturn (*func)(void*));
ThreadReturn thread_join(Thread thread);

void mutex_init(Mutex *mutex);
void mutex_free(Mutex *mutex);
void mutex_lock(Mutex *mutex);
void mutex_unlock(Mutex *mutex);

void condvar_init(Condvar *condvar);
void condvar_free(Condvar *condvar);
void condvar_wait(Condvar *condvar, Mutex *mutex);
void condvar_signal(Condvar *condvar);

ThreadReturn worker(void*)
{
    for (bool exit = false; !exit; ) {

        Job job = pop_job();

        switch (job.type) {

            case NO_JOB:
            exit = true;
            break;

            case JOB_A:
            http_response_builder_status(job.builder, 200);
            http_response_builder_body(job.builder, HTTP_STR("Job A completed"));
            http_response_builder_done(job.builder);
            break;

            case JOB_B:
            http_response_builder_status(job.builder, 200);
            http_response_builder_body(job.builder, HTTP_STR("Job B completed"));
            http_response_builder_done(job.builder);
            break;
        }
    }

    return 0;
}

int main(void)
{
    http_global_free();
    init_job_queue();

    HTTP_Server *server = http_server_init(HTTP_STR("127.0.0.1"), 8080);
    if (server == NULL)
        return -1;

    Thread worker_id;
    thread_create(&worker_id, NULL, worker);

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseBuilder builder;

        int ret = http_server_wait(server, &req, &builder);
        if (ret < 0) return -1;

        if (http_streq(req->url.path, HTTP_STR("/endpoint_A"))) {

            // Endpoint A sends the job to the worker.
            // If too many jobs are queued, it blocks

            Job job;
            job.type = JOB_A;
            job.builder = builder;
            push_job(job, true);
        
        } else if (http_streq(req->url.path, HTTP_STR("/endpoint_B"))) {

            // Endpoint B sends the job to the worker
            // but fails if the queue is full, in which
            // case the "503 Service Unavailable" response
            // is generated.

            Job job;
            job.type = JOB_B;
            job.builder = builder;
            if (!push_job(job, false)) {
                http_response_builder_status(builder, 503);
                http_response_builder_done(builder);
            }

        } else {

            // Other endpoints may resolve immediately

            http_response_builder_status(builder, 404);
            http_response_builder_done(builder);
        }
    }

    // Stop the worker by sending an empty job
    Job job;
    job.type = NO_JOB;
    push_job(job, true);
    thread_join(worker_id);

    http_server_free(server);
    free_job_queue();
    http_global_free();
    return 0;
}

//////////////////////////////////////////////

// This is a pretty standard condition variable-based
// producer-consumer queue. In this example we are using
// one worker, but we could easily have more than that.

Job     queue[MAX_JOBS];
int     queue_head = 0;
int     queue_count = 0;
Mutex   queue_lock;
Condvar queue_consume_event;
Condvar queue_produce_event;

void init_job_queue(void)
{
    mutex_init(&queue_lock);
    condvar_init(&queue_consume_event);
    condvar_init(&queue_produce_event);
}

void free_job_queue(void)
{
    condvar_free(&queue_produce_event);
    condvar_free(&queue_consume_event);
    mutex_free(&queue_lock);
}

Job pop_job(void)
{
    mutex_lock(&queue_lock);

    while (queue_count == 0)
        condvar_wait(&queue_produce_event, &queue_lock);

    Job job = queue[queue_head];
    queue_head = (queue_head + 1) % MAX_JOBS;
    queue_count--;

    condvar_signal(&queue_consume_event);
    mutex_unlock(&queue_lock);
    return job;
}

bool push_job(Job job, bool block)
{
    mutex_lock(&queue_lock);
    if (queue_count == 0) {

        if (!block) {
            mutex_unlock(&queue_lock);
            return false;
        }

        do
            condvar_wait(&queue_consume_event, &queue_lock);
        while (queue_count == 0);
    }

    int tail = (queue_head + queue_count) % MAX_JOBS;
    queue[tail] = job;
    queue_count++;

    condvar_signal(&queue_produce_event);
    mutex_unlock(&queue_lock);
    return true;
}

//////////////////////////////////////////////

void thread_create(Thread *thread, void *arg, ThreadReturn (*func)(void*))
{
#ifdef _WIN32
    Thread thread_ = CreateThread(NULL, 0, func, arg, 0, NULL);
    if (thread_ == INVALID_HANDLE_VALUE)
        abort();
    *thread = thread_;
#endif

#ifdef __linux__
    int ret = pthread_create(thread, NULL, func, arg);
    if (ret) abort();
#endif
}

ThreadReturn thread_join(Thread thread)
{
#ifdef _WIN32
    ThreadReturn result;
    WaitForSingleObject(thread, INFINITE);
    if (!GetExitCodeThread(thread, &result))
        abort();
    CloseHandle(thread);
    return result;
#endif

#ifdef __linux__
    ThreadReturn result;
    int ret = pthread_join(thread, &result);
    if (ret) abort();
    return result;
#endif
}

void mutex_init(Mutex *mutex)
{
#ifdef _WIN32
    InitializeCriticalSection(mutex);
#endif

#ifdef __linux__
    if (pthread_mutex_init(mutex, NULL))
        abort();
#endif
}

void mutex_free(Mutex *mutex)
{
#ifdef _WIN32
    DeleteCriticalSection(mutex);
#endif

#ifdef __linux__
    if (pthread_mutex_destroy(mutex))
        abort();
#endif
}

void mutex_lock(Mutex *mutex)
{
#ifdef _WIN32
    EnterCriticalSection(mutex);
#endif

#ifdef __linux__
    if (pthread_mutex_lock(mutex))
        abort();
#endif
}

void mutex_unlock(Mutex *mutex)
{
#ifdef _WIN32
    LeaveCriticalSection(mutex);
#endif

#ifdef __linux__
    if (pthread_mutex_unlock(mutex))
        abort();
#endif
}

void condvar_init(Condvar *condvar)
{
#ifdef _WIN32
    InitializeConditionVariable(condvar);
#endif

#ifdef __linux__
    if (pthread_cond_init(condvar, NULL))
        abort();
#endif
}

void condvar_free(Condvar *condvar)
{
#ifdef __linux__
    if (pthread_cond_destroy(condvar))
        abort();
#else
    (void) condvar;
#endif
}

void condvar_wait(Condvar *condvar, Mutex *mutex)
{
#ifdef _WIN32
    if (!SleepConditionVariableCS(condvar, mutex, INFINITE))
        abort();
#endif

#ifdef __linux__
    int err = pthread_cond_wait(condvar, mutex);
    if (err) abort();
#endif
}

void condvar_signal(Condvar *condvar)
{
#ifdef _WIN32
    WakeConditionVariable(condvar);
#endif

#ifdef __linux__
    if (pthread_cond_signal(condvar))
        abort();
#endif
}
