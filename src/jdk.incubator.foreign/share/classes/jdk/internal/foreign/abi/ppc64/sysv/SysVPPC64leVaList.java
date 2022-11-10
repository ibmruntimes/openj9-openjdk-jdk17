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

import java.lang.invoke.VarHandle;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import jdk.incubator.foreign.*;
import jdk.incubator.foreign.CLinker.VaList;
import jdk.internal.foreign.abi.ppc64.TypeClass;
import jdk.internal.foreign.abi.SharedUtils;
import jdk.internal.foreign.abi.SharedUtils.SimpleVaArg;
import jdk.internal.foreign.ResourceScopeImpl;
import static jdk.internal.foreign.PlatformLayouts.SysVPPC64le;

/**
 * This class implements VaList specific to Linux/ppc64le based on "64-Bit ELF V2 ABI
 * Specification: Power Architecture"(Revision 1.5), in which case the code is backported
 * from OpenJDK19 with modifications against the code of VaList on x64/windows as the template.
 *
 * va_arg impl on Linux/ppc64le:
 * typedef void * va_list;
 *
 * Specifically, va_list is simply a pointer (similar to the va_list on x64/windows) to a buffer
 * with all supportted types of arugments, including struct (passed by value), pointer and
 * primitive types, which are aligned with 8 bytes.
 */
public non-sealed class SysVPPC64leVaList implements VaList {
	public static final Class<?> CARRIER = MemoryAddress.class;

	/* Every primitive/pointer occupies 8 bytes and structs are aligned
	 * with 8 bytes in the total size when stacking the va_list buffer.
	 */
	private static final long VA_LIST_SLOT_BYTES = 8;
	private static final VaList EMPTY = new SharedUtils.EmptyVaList(MemoryAddress.NULL);

	private MemorySegment segment;
	private final ResourceScope scope;

	private SysVPPC64leVaList(MemorySegment segment, ResourceScope scope) {
		this.segment = segment;
		this.scope = scope;
	}

	public static final VaList empty() {
		return EMPTY;
	}

	@Override
	public int vargAsInt(MemoryLayout layout) {
		return Math.toIntExact((long)readArg(layout));
	}

	@Override
	public long vargAsLong(MemoryLayout layout) {
		return (long)readArg(layout);
	}

	@Override
	public double vargAsDouble(MemoryLayout layout) {
		return (double)readArg(layout);
	}

	@Override
	public MemoryAddress vargAsAddress(MemoryLayout layout) {
		return (MemoryAddress)readArg(layout);
	}

	@Override
	public MemorySegment vargAsSegment(MemoryLayout layout, SegmentAllocator allocator) {
		return (MemorySegment)readArg(layout, allocator);
	}

	@Override
	public MemorySegment vargAsSegment(MemoryLayout layout, ResourceScope scope) {
		return vargAsSegment(layout, SegmentAllocator.ofScope(scope));
	}

	private Object readArg(MemoryLayout argLayout) {
		return readArg(argLayout, SharedUtils.THROWING_ALLOCATOR);
	}

	private Object readArg(MemoryLayout argLayout, SegmentAllocator allocator) {
		Objects.requireNonNull(argLayout);
		Objects.requireNonNull(allocator);
		Object argument = null;

		TypeClass typeClass = TypeClass.classifyLayout(argLayout);
		long argByteSize = getAlignedArgSize(argLayout);

		switch (typeClass) {
			case PRIMITIVE, POINTER -> {
				VarHandle argHandle = TypeClass.classifyVarHandle((ValueLayout)argLayout);
				argument = argHandle.get(segment);
			}
			case STRUCT -> {
				/* With the smaller size of the allocated struct segment and the corresponding layout,
				 * it ensures the struct value is copied correctly from the va_list segment to the
				 * returned struct argument.
				 */
				argument = allocator.allocate(argLayout);
				long structByteSize = getSmallerStructArgSize((MemorySegment)argument, argLayout);
				((MemorySegment)argument).copyFrom(segment.asSlice(0, structByteSize));
			}
			default -> throw new IllegalStateException("Unsupported TypeClass: " + typeClass);
		}

		/* Move to the next argument in the va_list buffer */
		segment = segment.asSlice(argByteSize);
		return argument;
	}

	private static long getAlignedArgSize(MemoryLayout argLayout) {
		/* Always aligned with 8 bytes for primitives/pointer by default */
		long argLayoutSize = VA_LIST_SLOT_BYTES;

		/* As with primitives, a struct should aligned with 8 bytes */
		if (argLayout instanceof GroupLayout) {
			argLayoutSize = argLayout.byteSize();
			if ((argLayoutSize % VA_LIST_SLOT_BYTES) != 0) {
				argLayoutSize = (argLayoutSize / VA_LIST_SLOT_BYTES) * VA_LIST_SLOT_BYTES + VA_LIST_SLOT_BYTES;
			}
		}

		return argLayoutSize;
	}

	private static long getSmallerStructArgSize(MemorySegment structSegment, MemoryLayout structArgLayout) {
		return Math.min(structSegment.byteSize(), structArgLayout.byteSize());
	}

	@Override
	public void skip(MemoryLayout... layouts) {
		Objects.requireNonNull(layouts);
		((ResourceScopeImpl)scope).checkValidStateSlow();

		for (MemoryLayout layout : layouts) {
			Objects.requireNonNull(layout);
			long argByteSize = getAlignedArgSize(layout);
			/* Skip to the next argument in the va_list buffer */
			segment = segment.asSlice(argByteSize);
		}
	}

	public static VaList ofAddress(MemoryAddress addr, ResourceScope scope) {
		MemorySegment segment = addr.asSegment(Long.MAX_VALUE, scope);
		return new SysVPPC64leVaList(segment, scope);
	}

	@Override
	public ResourceScope scope() {
		return scope;
	}

	@Override
	public VaList copy() {
		((ResourceScopeImpl)scope).checkValidStateSlow();
		return new SysVPPC64leVaList(segment, scope);
	}

	@Override
	public MemoryAddress address() {
		return segment.address();
	}

	@Override
	public String toString() {
		return "SysVPPC64leVaList{" + segment.address() + '}';
	}

	static Builder builder(ResourceScope scope) {
		return new Builder(scope);
	}

	public static non-sealed class Builder implements VaList.Builder {
		private final ResourceScope scope;
		private final List<SimpleVaArg> stackArgs = new ArrayList<>();

		public Builder(ResourceScope scope) {
			((ResourceScopeImpl)scope).checkValidStateSlow();
			this.scope = scope;
		}

		private Builder setArg(MemoryLayout layout, Object value) {
			Objects.requireNonNull(layout);
			Objects.requireNonNull(value);
			Class<?> carrier = TypeClass.classifyCarrier(layout);
			SharedUtils.checkCompatibleType(carrier, layout, SysVPPC64leLinker.ADDRESS_SIZE);
			stackArgs.add(new SimpleVaArg(carrier, layout, value));
			return this;
		}

		@Override
		public Builder vargFromInt(ValueLayout layout, int value) {
			return setArg(layout, value);
		}

		@Override
		public Builder vargFromLong(ValueLayout layout, long value) {
			return setArg(layout, value);
		}

		@Override
		public Builder vargFromDouble(ValueLayout layout, double value) {
			return setArg(layout, value);
		}

		@Override
		public Builder vargFromAddress(ValueLayout layout, Addressable value) {
			return setArg(layout, value.address());
		}

		@Override
		public Builder vargFromSegment(GroupLayout layout, MemorySegment value) {
			return setArg(layout, value);
		}

		public VaList build() {
			if (stackArgs.isEmpty()) {
				return EMPTY;
			}

			/* All primitves/pointer (aligned with 8 bytes) are directly stored in the va_list buffer
			 * and all elements of stuct are totally copied to the va_list buffer (instead of storing
			 * the va_list address), in which case we need to calculate the total byte size of the
			 * buffer to be allocated for va_list.
			 */
			long totalArgsSize = stackArgs.stream().reduce(0L,
					(accum, arg) -> accum + getAlignedArgSize(arg.layout), Long::sum);
			SegmentAllocator allocator = SegmentAllocator.arenaAllocator(scope);
			MemorySegment segment = allocator.allocate(totalArgsSize);
			MemorySegment cursorSegment = segment;

			for (SimpleVaArg arg : stackArgs) {
				Object argValue = arg.value;
				MemoryLayout argLayout = arg.layout;
				long argByteSize = getAlignedArgSize(argLayout);
				TypeClass typeClass = TypeClass.classifyLayout(argLayout);

				switch (typeClass) {
					case PRIMITIVE, POINTER -> {
						VarHandle argHandle = TypeClass.classifyVarHandle((ValueLayout)argLayout);
						argHandle.set(cursorSegment, argValue);
					}
					case STRUCT -> {
						/* With the smaller size of the struct argument and the corresponding layout,
						 * it ensures the struct value is copied correctly from the struct argument
						 * to the va_list.
						 */
						MemorySegment structSegment = (MemorySegment)argValue;
						long structByteSize = getSmallerStructArgSize(structSegment, argLayout);
						cursorSegment.copyFrom(structSegment.asSlice(0, structByteSize));
					}
					default -> throw new IllegalStateException("Unsupported TypeClass: " + typeClass);
				}
				/* Move to the next argument by the aligned size of the current argument */
				cursorSegment = cursorSegment.asSlice(argByteSize);
			}
			return new SysVPPC64leVaList(segment, scope);
		}
	}
}
