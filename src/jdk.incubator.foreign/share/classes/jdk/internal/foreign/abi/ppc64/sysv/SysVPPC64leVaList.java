/*
 * Copyright (c) 2020, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2021, 2022 All Rights Reserved
 * ===========================================================================
 */

package jdk.internal.foreign.abi.ppc64.sysv;

import jdk.incubator.foreign.*;
import jdk.incubator.foreign.CLinker.VaList;
import jdk.internal.foreign.ResourceScopeImpl;
import jdk.internal.foreign.abi.SharedUtils;
import static jdk.internal.foreign.PlatformLayouts.SysVPPC64le;

/**
 * This file serves as a placeholder for VaList on Linux/ppc64le as the code
 * at Java level is not yet implemented for the moment. Futher analysis on
 * the struct is required to understand how the struct is laid out in memory
 * (e.g. the type & size of each field in va_list) and how the registers are
 * allocated for va_list.
 */
public non-sealed class SysVPPC64leVaList implements VaList {
    public static final Class<?> CARRIER = MemoryAddress.class;

    public static VaList empty() {
        throw new InternalError("empty() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public int vargAsInt(MemoryLayout layout) {
        throw new InternalError("vargAsInt() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public long vargAsLong(MemoryLayout layout) {
        throw new InternalError("vargAsLong() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public double vargAsDouble(MemoryLayout layout) {
        throw new InternalError("vargAsDouble() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public MemoryAddress vargAsAddress(MemoryLayout layout) {
        throw new InternalError("vargAsAddress() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public MemorySegment vargAsSegment(MemoryLayout layout, SegmentAllocator allocator) {
        throw new InternalError("vargAsSegment() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public MemorySegment vargAsSegment(MemoryLayout layout, ResourceScope scope) {
        throw new InternalError("vargAsSegment() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public void skip(MemoryLayout... layouts) {
        throw new InternalError("skip() is not yet implemented"); //$NON-NLS-1$
    }

    public static VaList ofAddress(MemoryAddress ma, ResourceScope scope) {
        throw new InternalError("ofAddress() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public ResourceScope scope() {
        throw new InternalError("scope() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public VaList copy() {
        throw new InternalError("copy() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public MemoryAddress address() {
        throw new InternalError("address() is not yet implemented"); //$NON-NLS-1$
    }

    @Override
    public String toString() {
        throw new InternalError("toString() is not yet implemented"); //$NON-NLS-1$
    }

    static SysVPPC64leVaList.Builder builder(ResourceScope scope) {
        return new SysVPPC64leVaList.Builder(scope);
    }

    public static non-sealed class Builder implements VaList.Builder {

        public Builder(ResourceScope scope) {
            throw new InternalError("Builder() is not yet implemented"); //$NON-NLS-1$
        }

        @Override
        public Builder vargFromInt(ValueLayout layout, int value) {
            throw new InternalError("vargFromInt() is not yet implemented"); //$NON-NLS-1$
        }

        @Override
        public Builder vargFromLong(ValueLayout layout, long value) {
            throw new InternalError("vargFromLong() is not yet implemented"); //$NON-NLS-1$
        }

        @Override
        public Builder vargFromDouble(ValueLayout layout, double value) {
            throw new InternalError("vargFromDouble() is not yet implemented"); //$NON-NLS-1$
        }

        @Override
        public Builder vargFromAddress(ValueLayout layout, Addressable value) {
            throw new InternalError("vargFromAddress() is not yet implemented"); //$NON-NLS-1$
        }

        @Override
        public Builder vargFromSegment(GroupLayout layout, MemorySegment value) {
            throw new InternalError("vargFromSegment() is not yet implemented"); //$NON-NLS-1$
        }

        public VaList build() {
            throw new InternalError("build() is not yet implemented"); //$NON-NLS-1$
        }
    }
}
