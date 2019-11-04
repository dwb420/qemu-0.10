/*
 * QEMU low level functions
 *
 * Copyright (c) 2003 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu-common.h"
#include "sysemu.h"

#include <malloc.h>

#include "qemu_socket.h"

void *qemu_memalign(size_t alignment, size_t size)
{
#if defined(_POSIX_C_SOURCE)
    int ret;
    void *ptr;
    ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0)
        return NULL;
    return ptr;
#else
    return memalign(alignment, size);
#endif
}

/* alloc shared memory pages */
void *qemu_vmalloc(size_t size)
{
    return qemu_memalign(getpagesize(), size);
}

void qemu_vfree(void *ptr)
{
    free(ptr);
}

int qemu_create_pidfile(const char *filename)
{
    char buffer[128];
    int len;
    int fd;

    fd = open(filename, O_RDWR | O_CREAT, 0600);
    if (fd == -1)
        return -1;

    if (lockf(fd, F_TLOCK, 0) == -1)
        return -1;

    len = snprintf(buffer, sizeof(buffer), "%ld\n", (long)getpid());
    if (write(fd, buffer, len) != len)
        return -1;

    return 0;
}

void socket_set_nonblock(int fd)
{
    int f;
    f = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, f | O_NONBLOCK);
}
