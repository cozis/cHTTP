#include <stdbool.h>
#include <chttp.h>

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
    HTTP_ResponseHandle res;
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

void *worker(void*)
{
    for (bool exit = false; !exit; ) {

        Job job = pop_job();

        switch (job.type) {

            case NO_JOB:
            exit = true;
            break;

            case JOB_A:
            http_response_status(job.res, 200);
            http_response_body(job.res, HTTP_STR("Job A completed"));
            http_response_done(job.res);
            break;

            case JOB_B:
            http_response_status(job.res, 200);
            http_response_body(job.res, HTTP_STR("Job B completed"));
            http_response_done(job.res);
            break;
        }
    }

    return NULL;
}

int main(void)
{
    init_job_queue();

    HTTP_Server *server = http_server_init(HTTP_STR("127.0.0.1"), 8080);
    if (server == NULL)
        return -1;

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseHandle res;

        int ret = http_server_wait(server, &res, &res);
        if (ret < 0) return -1;

        if (http_streq(req->url.path, HTTP_STR("/endpoint_A"))) {

            // Endpoint A sends the job to the worker.
            // If too many jobs are queued, it blocks

            Job job;
            job.type = JOB_A;
            job.res  = res;
            push_job(job, true);
        
        } else if (http_streq(req->url.path, HTTP_STR("/endpoint_B"))) {

            // Endpoint B sends the job to the worker
            // but fails if the queue is full, in which
            // case the "503 Service Unavailable" response
            // is generated.

            Job job;
            job.type = JOB_B;
            job.res = res;
            if (!push_job(job, false)) {
                http_response_status(res, 503);
                http_response_done(res);
            }

        } else {

            // Other endpoints may resolve immediately

            http_response_status(res, 404);
            http_response_done(res);
        }
    }

    // Stop the worker by sending an empty job
    Job job;
    job.type = NO_JOB;
    push_job(job, true);

    http_server_free(server);
    free_job_queue();
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

    while (queue_count == 0);
        condvar_wait(&queue_produce_event, &queue_lock, -1);

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
            condvar_wait(&queue_consume_event, &queue_lock, -1);
        while (queue_count == 0);
    }

    int tail = (queue_head + queue_count) % MAX_JOBS;
    queue[tail] = job;
    queue_count++;

    condvar_signal(&queue_produce_event);
    mutex_unlock(&queue_lock);
    return true;
}
