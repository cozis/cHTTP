
void byte_queue_init(ByteQueue *queue, uint32_t limit)
{
    queue->flags = 0;
    queue->head = 0;
    queue->size = 0;
    queue->used = 0;
    queue->curs = 0;
    queue->limit = limit;
    queue->data = NULL;
    queue->read_target = NULL;
}

// Deinitialize the queue
void byte_queue_free(ByteQueue *queue)
{
    if (queue->read_target) {
        if (queue->read_target != queue->data)
            free(queue->read_target);
        queue->read_target = NULL;
        queue->read_target_size = 0;
    }

    free(queue->data);
    queue->data = NULL;
}

int byte_queue_error(ByteQueue *queue)
{
    return queue->flags & BYTE_QUEUE_ERROR;
}

int byte_queue_empty(ByteQueue *queue)
{
    return queue->used == 0;
}

int byte_queue_full(ByteQueue *queue)
{
    return queue->used == queue->limit;
}

ByteView byte_queue_read_buf(ByteQueue *queue)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return (ByteView) {NULL, 0};

    assert((queue->flags & BYTE_QUEUE_READ) == 0);
    queue->flags |= BYTE_QUEUE_READ;
    queue->read_target      = queue->data;
    queue->read_target_size = queue->size;

    if (queue->data == NULL)
        return (ByteView) {NULL, 0};

    return (ByteView) { queue->data + queue->head, queue->used };
}

void byte_queue_read_ack(ByteQueue *queue, uint32_t num)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    if ((queue->flags & BYTE_QUEUE_READ) == 0)
        return;

    queue->flags &= ~BYTE_QUEUE_READ;

    assert((uint32_t) num <= queue->used);
    queue->head += (uint32_t) num;
    queue->used -= (uint32_t) num;
    queue->curs += (uint32_t) num;

    if (queue->read_target) {
        if (queue->read_target != queue->data)
            free(queue->read_target);
        queue->read_target = NULL;
        queue->read_target_size = 0;
    }
}

ByteView byte_queue_write_buf(ByteQueue *queue)
{
    if ((queue->flags & BYTE_QUEUE_ERROR) || queue->data == NULL)
        return (ByteView) {NULL, 0};

    assert((queue->flags & BYTE_QUEUE_WRITE) == 0);
    queue->flags |= BYTE_QUEUE_WRITE;

    return (ByteView) {
        queue->data + (queue->head + queue->used),
        queue->size - (queue->head + queue->used),
    };
}

void byte_queue_write_ack(ByteQueue *queue, uint32_t num)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    if ((queue->flags & BYTE_QUEUE_WRITE) == 0)
        return;

    queue->flags &= ~BYTE_QUEUE_WRITE;
    queue->used += num;
}

int byte_queue_write_setmincap(ByteQueue *queue, uint32_t mincap)
{
    // Sticky error
    if (queue->flags & BYTE_QUEUE_ERROR)
        return 0;

    // In general, the queue's contents look like this:
    //
    //                           size
    //                           v
    //   [___xxxxxxxxxxxx________]
    //   ^   ^           ^
    //   0   head        head + used
    //
    // This function needs to make sure that at least [mincap]
    // bytes are available on the right side of the content.
    //
    // We have 3 cases:
    //
    //   1) If there is enough memory already, this function doesn't
    //      need to do anything.
    //
    //   2) If there isn't enough memory on the right but there is
    //      enough free memory if we cound the left unused region,
    //      then the content is moved back to the
    //      start of the buffer.
    //
    //   3) If there isn't enough memory considering both sides, this
    //      function needs to allocate a new buffer.
    //
    // If there are pending read or write operations, the application
    // is holding pointers to the buffer, so we need to make sure
    // to not invalidate them. The only real problem is pending reads
    // since this function can only be called before starting a write
    // opearation.
    //
    // To avoid invalidating the read pointer when we allocate a new
    // buffer, we don't free the old buffer. Instead, we store the
    // pointer in the "old" field so that the read ack function can
    // free it.
    //
    // To avoid invalidating the pointer when we are moving back the
    // content since there is enough memory at the start of the buffer,
    // we just avoid that. Even if there is enough memory considering
    // left and right free regions, we allocate a new buffer.

    assert((queue->flags & BYTE_QUEUE_WRITE) == 0);

    uint32_t total_free_space = queue->size - queue->used;
    uint32_t free_space_after_data = queue->size - queue->used - queue->head;

    int moved = 0;
    if (free_space_after_data < mincap) {

        if (total_free_space < mincap || (queue->read_target == queue->data)) {
            // Resize required

            if (queue->used + mincap > queue->limit) {
                queue->flags |= BYTE_QUEUE_ERROR;
                return 0;
            }

            uint32_t size;
            if (queue->size > UINT32_MAX / 2)
                size = UINT32_MAX;
            else
                size = 2 * queue->size;

            if (size < queue->used + mincap)
                size = queue->used + mincap;

            if (size > queue->limit)
                size = queue->limit;

            char *data = malloc(size);
            if (!data) {
                queue->flags |= BYTE_QUEUE_ERROR;
                return 0;
            }

            if (queue->used > 0)
                memcpy(data, queue->data + queue->head, queue->used);

            if (queue->read_target != queue->data)
                free(queue->data);

            queue->data = data;
            queue->head = 0;
            queue->size = size;

        } else {
            // Move required
            memmove(queue->data, queue->data + queue->head, queue->used);
            queue->head = 0;
        }

        moved = 1;
    }

    return moved;
}

void byte_queue_write(ByteQueue *queue, void *ptr, uint32_t len)
{
    byte_queue_write_setmincap(queue, len);
    ByteView dst = byte_queue_write_buf(queue);
    if (dst.ptr) {
        memcpy(dst.ptr, ptr, len);
        byte_queue_write_ack(queue, len);
    }
}

void byte_queue_write_fmt2(ByteQueue *queue,
    const char *fmt, va_list args)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	va_list args2;
	va_copy(args2, args);

	byte_queue_write_setmincap(queue, 128);
	ByteView dst = byte_queue_write_buf(queue);

	int len = vsnprintf(dst.ptr, dst.len, fmt, args);
	if (len < 0) {
		queue->flags |= BYTE_QUEUE_ERROR;
		va_end(args2);
		return;
	}

	if ((size_t) len > dst.len) {
		byte_queue_write_ack(queue, 0);
		byte_queue_write_setmincap(queue, len+1);
		dst = byte_queue_write_buf(queue);
		vsnprintf(dst.ptr, dst.len, fmt, args2);
	}

	byte_queue_write_ack(queue, len);

	va_end(args2);
}

void byte_queue_write_fmt(ByteQueue *queue,
    const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	byte_queue_write_fmt2(queue, fmt, args);
	va_end(args);
}

ByteQueueOffset byte_queue_offset(ByteQueue *queue)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return (ByteQueueOffset) { 0 };
    return (ByteQueueOffset) { queue->curs + queue->used };
}

void byte_queue_patch(ByteQueue *queue, ByteQueueOffset off,
    void *src, uint32_t len)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    // Check that the offset is in range
    assert(off >= queue->curs && off - queue->curs < queue->used);

    // Check that the length is in range
    assert(len <= queue->used - (off - queue->curs));

    // Perform the patch
    char *dst = queue->data + queue->head + (off - queue->curs);
    memcpy(dst, src, len);
}

uint32_t byte_queue_size_from_offset(ByteQueue *queue, ByteQueueOffset off)
{
    return queue->curs + queue->used - off;
}

void byte_queue_remove_from_offset(ByteQueue *queue, ByteQueueOffset offset)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    uint64_t num = (queue->curs + queue->used) - offset;
    assert(num <= queue->used);

    queue->used -= num;
}
