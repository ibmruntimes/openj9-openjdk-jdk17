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
package sun.nio.ch;

import sun.security.action.GetPropertyAction;

/**
 * This class is used to set the flag to enable the Pollset implementation in NIO classes.
 *
 * Enabled only when:
 *   - System property java.nio.channels.spi.SelectorProvider equals
 *     "sun.nio.ch.PollsetSelectorProvider"
 *   - AND the OS is AIX.
 */
public final class PollsetSelectorFeature {

    public static final boolean ENABLED;

    static {
        ENABLED = isNativePollsetAvailable()
                && "sun.nio.ch.PollsetSelectorProvider".equals(
                        GetPropertyAction.privilegedGetProperty("java.nio.channels.spi.SelectorProvider"));
    }

    private PollsetSelectorFeature() {
    }

    private static native boolean isNativePollsetAvailable();
}
