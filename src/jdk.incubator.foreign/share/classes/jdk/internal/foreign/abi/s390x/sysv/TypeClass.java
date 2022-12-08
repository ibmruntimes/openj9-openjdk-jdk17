/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
 * ===========================================================================
 */

package jdk.internal.foreign.abi.s390x.sysv;

import java.lang.invoke.VarHandle;
import java.util.List;

import jdk.incubator.foreign.GroupLayout;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.ValueLayout;
import static jdk.incubator.foreign.CLinker.*;
import static jdk.incubator.foreign.ValueLayout.*;
import jdk.internal.foreign.abi.SharedUtils;

/**
 * This class enumerates three argument types for Linux/s390x against the implementation
 * of TypeClass on Linux/ppc64le.
 */
enum TypeClass {
	INTEGER, /* Intended for all integral primitive types */
	FLOAT,   /* Intended for float and double */
	POINTER,
	STRUCT,
	STRUCT_ONE_FLOAT; /* Intended for a struct with only one float or double element */

	static boolean isFloatingType(MemoryLayout layout) {
		boolean isFPR = false;

		if ((layout instanceof ValueLayout) && (classifyValueType((ValueLayout)layout) == FLOAT)
			|| (layout instanceof GroupLayout) && isStructWithOneFloat((GroupLayout)layout)
		) {
			isFPR = true;
		}

		return isFPR;
	}

	private static boolean isStructWithOneFloat(GroupLayout structLayout) {
		List<MemoryLayout> elemLayoutList = structLayout.memberLayouts();
		boolean hasOneFloat = false;

		if (elemLayoutList.size() == 1) {
			MemoryLayout elemLayout = elemLayoutList.get(0);
			if ((elemLayout instanceof ValueLayout)
				&& (classifyValueType((ValueLayout)elemLayout) == FLOAT)
			) {
				hasOneFloat = true;
			}
		}

		return hasOneFloat;
	}

	static VarHandle classifyVarHandle(MemoryLayout layout) {
		Class<?> carrier = classifyCarrier(layout);
		VarHandle argHandle = null;

		/* According to the API Spec, all non-long integral types are promoted
		 * to long (8 bytes) while a float is promoted to double.
		 */
		if ((carrier == byte.class)
			|| (carrier == char.class)
			|| (carrier == short.class)
			|| (carrier == int.class)
			|| (carrier == long.class)
		) {
			argHandle = SharedUtils.vhPrimitiveOrAddress(long.class, C_LONG_LONG);
		} else if ((carrier == float.class)
			|| (carrier == double.class)
		) {
			argHandle = SharedUtils.vhPrimitiveOrAddress(double.class, C_DOUBLE);
		/* VarHandle stores the address of struct which is greater than 8 bytes in size as per the ABI document */
		} else if ((carrier == MemoryAddress.class)
			|| (carrier == MemorySegment.class)
		) {
			argHandle = SharedUtils.vhPrimitiveOrAddress(MemoryAddress.class, C_POINTER);
		} else {
			throw new IllegalStateException("Unspported carrier: " + carrier.getName());
		}

		return argHandle;
	}

	static Class<?> classifyCarrier(MemoryLayout layout) {
		Class<?> carrier = null;

		if (layout instanceof ValueLayout) {
			carrier = classifyValueLayoutCarrier((ValueLayout)layout);
		} else if (layout instanceof GroupLayout) {
			carrier = MemorySegment.class;
		} else {
			throw new IllegalArgumentException("Unsupported layout: " + layout);
		}

		return carrier;
	}

	private static Class<?> classifyValueLayoutCarrier(ValueLayout layout) {
		Class<?> carrier = null;

		/* Extract the kind from the specified layout with the ATTR_NAME "abi/kind".
		 * e.g. b32[abi/kind=INT]
		 */
		TypeKind kind = (TypeKind)layout.attribute(TypeKind.ATTR_NAME)
				.orElseThrow(() -> new IllegalArgumentException("The layout's ABI class is empty"));

		switch (kind) {
		case CHAR:
			carrier = byte.class;
			break;
		case SHORT:
			carrier = short.class;
			break;
		case INT:
			carrier = int.class;
			break;
		case LONG: /* Fall through */
		case LONG_LONG:
			carrier = long.class;
			break;
		case FLOAT:
			carrier = float.class;
			break;
		case DOUBLE:
			carrier = double.class;
			break;
		case POINTER:
			carrier = MemoryAddress.class;
			break;
		default:
			throw new IllegalArgumentException("The layout's ABI Class is undefined: layout = " + layout);
		}

		return carrier;
	}

	static TypeClass classifyLayout(MemoryLayout layout) {
		TypeClass layoutType = null;

		if (layout instanceof ValueLayout) {
			layoutType = classifyValueType((ValueLayout)layout);
		} else if (layout instanceof GroupLayout) {
			if (isStructWithOneFloat((GroupLayout)layout)) {
				layoutType = STRUCT_ONE_FLOAT;
			} else {
				layoutType = STRUCT;
			}
		} else {
			throw new IllegalArgumentException("Unsupported layout: " + layout);
		}

		return layoutType;
	}

	private static TypeClass classifyValueType(ValueLayout layout) {
		TypeClass layoutType = null;

		/* Extract the kind from the specified layout with the ATTR_NAME "abi/kind".
		 * e.g. b32[abi/kind=INT]
		 */
		TypeKind kind = (TypeKind)layout.attribute(TypeKind.ATTR_NAME)
				.orElseThrow(() -> new IllegalArgumentException("The layout's ABI class is empty"));

		switch (kind) {
		case CHAR:        /* Fall through */
		case SHORT:       /* Fall through */
		case INT:         /* Fall through */
		case LONG:        /* Fall through */
		case LONG_LONG:
			layoutType = INTEGER;
			break;
		case FLOAT:       /* Fall through */
		case DOUBLE:
			layoutType = FLOAT;
			break;
		case POINTER:
			layoutType = POINTER;
			break;
		default:
			throw new IllegalArgumentException("The layout's ABI Class is undefined: layout = " + layout);
		}

		return layoutType;
	}
}
