/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2025, 2026 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */
#include "jni.h"
#include "jni_util.h"
#include "jvm.h"
#include "jlong.h"

#include "sun_nio_ch_PollsetArrayWrapper.h"

#include <unistd.h>
#include <sys/pollset.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <poll.h>

#include "net_util.h"

#define RESTARTABLE(_cmd, _result) \
    do { \
        (_result) = (_cmd); \
    } while (((_result) == -1) && (errno == EINTR))

typedef int pollset_t;

static short POLLFD_SIZE = (short)(sizeof(struct pollfd));

static int
iepoll(int pollsetFD, struct pollfd *events, int numfds, jlong timeout)
{
    jlong start = 0;
    jlong now = 0;
    int remaining = timeout;
    struct timeval t;
    jlong diff = 0;

    gettimeofday(&t, NULL);
    start = (t.tv_sec * 1000) + (t.tv_usec / 1000);

    for (;;) {
        int res = pollset_poll(pollsetFD, events, numfds, timeout);
        if ((res < 0) && (errno == EINTR)) {
            if (remaining >= 0) {
                gettimeofday(&t, NULL);
                now = (t.tv_sec * 1000) + (t.tv_usec / 1000);
                diff = now - start;
                remaining -= diff;
                if ((diff < 0) || (remaining <= 0)) {
                    return 0;
                }
                start = now;
            }
        } else {
            return res;
        }
    }
}

JNIEXPORT jint JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_pollsetCreate(JNIEnv *env, jobject this, jint maxfd)
{
    /*
     * pollset_create() creates a new and independent pollset. The maximum number
     * of file descriptors that can belong to the pollset is specified by maxfd.
     */

    int pollsetFD = pollset_create(maxfd);
    if (pollsetFD < 0) {
       JNU_ThrowIOExceptionWithLastError(env, "pollset_create failed");
    }
    return pollsetFD;
}

/* helper methods to get size of the structures and offsets */
JNIEXPORT jshort JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_getPollfdSize(JNIEnv *env, jobject this)
{
    return (jshort) POLLFD_SIZE;
}

JNIEXPORT jshort JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_getPollCtlSize(JNIEnv *env, jobject this)
{
    return (jshort) (sizeof(struct poll_ctl));
}

JNIEXPORT jshort JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_getSizeOfInt(JNIEnv *env, jobject this)
{
    return (jshort) (sizeof(int));
}

JNIEXPORT jint JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_fdLimit(JNIEnv *env, jclass this)
{
    struct rlimit rlp;
    if (getrlimit(RLIMIT_NOFILE, &rlp) < 0) {
        JNU_ThrowIOExceptionWithLastError(env, "getrlimit failed");
    }
    return (jint) rlp.rlim_cur;
}

JNIEXPORT void JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_pollsetCtl(JNIEnv *env, jobject this,
                                jint pollsetFD, jshort cmd, jshort events, jint fd)
{
    struct poll_ctl pollCtl;
    int res = 0;

    memset(&pollCtl, 0, sizeof(pollCtl));
    pollCtl.cmd = (short) cmd;
    pollCtl.events = (short) events;
    pollCtl.fd = (int) fd;

    RESTARTABLE(pollset_ctl(pollsetFD, &pollCtl, 1), res);

    /*
     * A channel may be registered with several Selectors. When each Selector
     * is polled a PS_DEL op will be inserted into its pending update
     * list to remove the file descriptor from pollset. The "last" Selector will
     * close the file descriptor which automatically unregisters it from each
     * pollset descriptor. To avoid costly synchronization between Selectors we
     * allow pending updates to be processed, ignoring errors. The errors are
     * harmless as the last update for the file descriptor is guaranteed to
     * be PS_DEL.
     */
    if ((res < 0) && (errno != EBADF) && (errno != ENOENT) && (errno != EINVAL) && (errno != EPERM)) {
        JNU_ThrowIOExceptionWithLastError(env, "pollset_ctl failed");
    }
}

JNIEXPORT void JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_pollsetBulkCtl(JNIEnv *env, jobject this,
                                jint pollsetFD, jlong address, jint count)
{
    /*
     * Upon success, pollset_ctl returns 0. Upon failure, pollset_ctl returns the
     * 0-based problem element number of the pollctl_array (for example, 2 is returned
     * for element 3). If the first element is the problem element, or some other error
     * occurs prior to processing the array of elements, -1 is returned and errno is
     * set to the appropriate code. The calling application must acknowledge that elements
     * in the array prior to the problem element were successfully processed and should
     * attempt to call pollset_ctl again with the elements of pollctl_array beyond the
     * problematic element.
     */

    int res = 0;

    while (count > 0) {
        res = pollset_ctl(pollsetFD, address, count);
        if (res == 0) {
            break;
        } else if (res == -1) {
            if (errno == EINTR) {
                continue;
            }
            address += POLLFD_SIZE;
            count -= 1;
        } else {
            address += (res + 1) * POLLFD_SIZE;
            count -= (res + 1);
        }
    }

    if ((res < 0) && (errno != EBADF) && (errno != ENOENT) && (errno != EINVAL) && (errno != EPERM)) {
        JNU_ThrowIOExceptionWithLastError(env, "pollset_ctl failed");
    }
}

JNIEXPORT jint JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_pollsetPoll(JNIEnv *env, jobject this,
                                            jint pollsetFD, jlong address,
                                            jint numfds, jlong timeout)
{
    struct pollfd *events = (struct pollfd *) jlong_to_ptr(address);
    int res = 0;

    if (timeout <= 0) {           /* Indefinite or no wait. */
        RESTARTABLE(pollset_poll(pollsetFD, events, numfds, timeout), res);
    } else {                      /* Bounded wait; bounded restarts. */
        res = iepoll(pollsetFD, events, numfds, timeout);
    }

    if (res < 0) {
        JNU_ThrowIOExceptionWithLastError(env, "pollset_poll failed");
    }
    return res;
}

JNIEXPORT void JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_interrupt(JNIEnv *env, jobject this, jint fd)
{
    char fakebuf = 0;
    if (write(fd, &fakebuf, 1) < 0) {
        JNU_ThrowIOExceptionWithLastError(env,"write to interrupt fd failed");
    }
}

JNIEXPORT jint JNICALL
Java_sun_nio_ch_PollsetArrayWrapper_pollsetDestroy(JNIEnv *env, jobject this, jint pollsetFD)
{
    if (pollset_destroy(pollsetFD) < 0) {
        JNU_ThrowIOExceptionWithLastError(env,"pollset_destroy failed");
    }
}
