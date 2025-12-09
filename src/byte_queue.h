// This is the implementation of a byte queue useful
// for systems that need to process engs of bytes.
//
// It features sticky errors, a zero-copy interface,
// and a safe mechanism to patch previously written
// bytes.
//
// Only up to 4GB of data can be stored at once.

// Internal use only
enum {
    BYTE_QUEUE_ERROR = 1 << 0,
    BYTE_QUEUE_READ  = 1 << 1,
    BYTE_QUEUE_WRITE = 1 << 2,
};

typedef struct {
    char  *ptr;
    size_t len;
} ByteView;

// Fields are for internal use only
typedef struct {
    uint64_t curs;
    char*    data;
    uint32_t head;
    uint32_t size;
    uint32_t used;
    uint32_t limit;
    char*    read_target;
    uint32_t read_target_size;
    int flags;
} ByteQueue;

// Represents an offset inside the queue relative
// to the first byte ever appended to the queue,
// therefore consuming bytes from the queue does
// not invalidate this type of offset.
typedef uint64_t ByteQueueOffset;

// Initialize the queue with a given capacity limit.
// This is just a soft limit. The queue will allocate
// dynamically as needed up to this limit and won't
// grow further. When the limit is reached, chttp_queue_full
// returns true.
void byte_queue_init(ByteQueue *queue, uint32_t limit);

// Free resources associated to this queue
void byte_queue_free(ByteQueue *queue);

// Check whether an error occurred inside the queue
int byte_queue_error(ByteQueue *queue);

// Returns 1 if the queue has no bytes inside it,
// or 0 otherwise.
int byte_queue_empty(ByteQueue *queue);

// Returns 1 if the queue reached its limit, or 0
// otherwise.
int byte_queue_full(ByteQueue *queue);

// These two functions are to be used together.
// read_buf returns a view into the queue of the
// bytes that can be read from it. The caller can
// decide how many of those bytes can be removed
// by passing the count to the read_ack function.
// If an error occurred inside the queue, this
// function returns an empty view.
//
// Note that the calls to read_buf and read_ack
// may be far apart. Other operations won't interfere
// with the read. The only rule is you can't call
// read_buf multiple times before calling read_ack.
ByteView byte_queue_read_buf(ByteQueue *queue);
void     byte_queue_read_ack(ByteQueue *queue, uint32_t num);

// Similar to the read_buf/read_ack functions,
// but write_buf returns a view of the unused
// memory inside the queue, and write_ack is
// used to tell the queue how many bytes were
// written into it. Note that to ensure there
// is a minimum amount of free space in the queue,
// the user needs to call byte_queue_setmincap.
// If an error occurred inside the queue, this
// function returns an empty view.
//
// Note that the calls to write_buf and write_ack
// may be far apart. Other operations won't interfere
// with the write (except for other byte_queue_write_*
// functions). The only rule is you can't call
// write_buf multiple times before calling write_ack.
ByteView byte_queue_write_buf(ByteQueue *queue);
void     byte_queue_write_ack(ByteQueue *queue, uint32_t num);

// Sets the minimum capacity for the next write
// operation and returns 1 if the content of the
// queue was moved, else 0 is returned.
//
// You must not call this function while a write
// is pending. In other words, you must do this:
//
//   byte_queue_write_setmincap(queue, mincap);
//   dst = byte_queue_write_buf(queue, &cap);
//   ...
//   byte_queue_write_ack(num);
//
// And NOT this:
//
//   dst = byte_queue_write_buf(queue);
//   byte_queue_write_setmincap(queue, mincap); <-- BAD
//   ...
//   byte_queue_write_ack(num);
//
int byte_queue_write_setmincap(ByteQueue *queue, uint32_t mincap);

// Write some bytes to the queue. This is a
// short hand for write_buf/memcpy/write_ack
void byte_queue_write(ByteQueue *queue, void *ptr, uint32_t len);

// Write the result of the format into the queue
void byte_queue_write_fmt(ByteQueue *queue, const char *fmt, ...);

// Write the result of the format into the queue
void byte_queue_write_fmt2(ByteQueue *queue, const char *fmt,
    va_list args);

// Returns the current offset inside the queue
ByteQueueOffset byte_queue_offset(ByteQueue *queue);

// Writes some bytes at the specified offset. It's
// the responsibility of the user to make sure that
// the offset still refers to content inside the queue.
void byte_queue_patch(ByteQueue *queue, ByteQueueOffset off, void *src, uint32_t len);

// Returns the number of bytes from the given offset
// to the end of the queue.
uint32_t byte_queue_size_from_offset(ByteQueue *queue, ByteQueueOffset off);

// Removes all bytes from the given offset to the the
// end of the queue.
void byte_queue_remove_from_offset(ByteQueue *queue, ByteQueueOffset offset);
