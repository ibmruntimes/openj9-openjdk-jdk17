/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2026, 2026 All Rights Reserved
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

#include <jni.h>

#if defined(_AIX)
#include <sys/pollset.h>
#endif /* defined(_AIX) */

JNIEXPORT jboolean JNICALL
Java_sun_nio_ch_PollsetSelectorFeature_isNativePollsetAvailable
  (JNIEnv *env, jclass cls)
{
    jboolean pollsetAvailable = JNI_FALSE;
#if defined(_AIX)
    int ps = pollset_create(-1);

    if (ps >= 0) {
        pollsetAvailable = JNI_TRUE;
        pollset_destroy(ps);
    }
#endif /* defined(_AIX) */
    return pollsetAvailable;
}
