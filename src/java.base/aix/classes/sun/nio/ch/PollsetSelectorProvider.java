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

import java.io.IOException;
import java.nio.channels.Channel;
import java.nio.channels.spi.AbstractSelector;
import java.nio.channels.spi.SelectorProvider;

/**
 * SelectorProvider implementation that creates PollsetSelector instances.
 */
public class PollsetSelectorProvider
    extends SelectorProviderImpl
{
    /**
     * Opens a selector for this provider.
     *
     * If the pollset feature is enabled and supported by the underlying
     * AIX operating system, this method returns PollsetSelectorImpl,
     * which uses the native pollset API for scalable I/O event notification.
     *
     * If the pollset API is not available this method falls back to the
     * PollSelectorImpl, ensuring compatibility with systems that
     * do not support pollset.
     */
    @Override
    public AbstractSelector openSelector() throws IOException {
        if (PollsetSelectorFeature.ENABLED) {
            return new PollsetSelectorImpl(this);
        }
        return new PollSelectorImpl(this);
    }

    /**
     * Returns the inherited channel, if any.
     */
    @Override
    public Channel inheritedChannel() throws IOException {
        return InheritedChannel.getChannel();
    }
}
