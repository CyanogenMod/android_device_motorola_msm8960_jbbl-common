/*
 * Copyright (C) 2016 The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* gcc -shared -fPIC -o libwrapper.so wrapper.c -ldl */
/* LD_PRELOAD=libwrapper.so bin/executable */

/* RTLD_NEXT */
#define _GNU_SOURCE

#define LOG_TAG "qmuxdwrapper"

#include <cutils/log.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

static int (*real_open)(const char *, int, ...);
static int (*real_read)(int, void *, size_t);
static int (*real_close)(int);

#define PROBLEM_PATH             "/dev/smdcntl1"
#define MAX_FAILED_READS         3
#define DISCARD_MAX_PACKET_SIZE  8192

/* Looks like this is supposed to be a kernel-internal code, it is not in
 * uapi errno.h */
#define ETOOSMALL 525

static int problem_fd = -1;

static void *get_real(const char *symbol)
{
    void *sym = dlsym(RTLD_NEXT, symbol);

    if (!sym) {
        ALOGE("Wrapper failed to find symbol '%s', this will crash\n", symbol);
    }

    return sym;
}

/*
 * It seems open/read may be called *very* early, so we can't just use e.g.
 * __attribute__((constructor)) to initialize the function pointers.
 */

int open(const char *filename, int flags, ...) {
    int fd;

    if (real_open == NULL)
        *(void **)&real_open = get_real("open");

    if (flags & O_CREAT) {
        va_list args;
        int mode;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
        return real_open(filename, flags, mode);
    }

    fd = real_open(filename, flags);

    if (strcmp(filename, PROBLEM_PATH) == 0) {
        ALOGI("Wrapping read accesses to %s (fd %d)\n", filename, fd);
        problem_fd = fd;
    }

    return fd;
}

static void discard_large_packet(int fd) {
    static char dummybuf[DISCARD_MAX_PACKET_SIZE];

    ssize_t ret = real_read(fd, dummybuf, sizeof(dummybuf));
    if (ret >= 0)
        ALOGI("Discarded %d bytes to avoid stuck qmuxd\n", ret);
    else
        ALOGE("Wrapped read failed: %d\n", errno);
}

ssize_t read(int fd, void *buf, size_t count) {
    static int consecutive_too_small_reads = 0;
    ssize_t ret;

    if (real_read == NULL)
        *(void **)&real_read = get_real("read");

    ret = real_read(fd, buf, count);

    if (fd == problem_fd) {
        if (ret == -1 && errno == ETOOSMALL) {
            consecutive_too_small_reads++;

            /*
             * Observed hitting this situation with the incoming packet size
             * being 5434 with qmuxd using a buffer sized 2014 on /dev/smdcntl1
             * (DATA6_CNTL) on XT897 on Elisa Saunalahti network shortly after
             * most bootups, with the message being repeated every second.
             * Mobile data would not go up again until a reboot (though an
             * ongoing connection would continue to work).
             *
             * To avoid that, discard the packet after consecutive failures to
             * read anything due to too small a buffer.
             */
            if (consecutive_too_small_reads >= MAX_FAILED_READS) {
                discard_large_packet(fd);
                consecutive_too_small_reads = 0;

                /* perform the original read again */
                ret = real_read(fd, buf, count);
            }

        } else {
            consecutive_too_small_reads = 0;
        }
    }

    return ret;
}

int close(int fd)
{
    if (real_close == NULL)
        *(void **)&real_close = get_real("close");

    if (fd == problem_fd)
        problem_fd = -1;

    return real_close(fd);
}
