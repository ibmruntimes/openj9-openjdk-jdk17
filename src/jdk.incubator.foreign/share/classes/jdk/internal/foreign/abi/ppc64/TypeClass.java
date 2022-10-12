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

package jdk.internal.foreign.abi.ppc64;

import java.lang.invoke.VarHandle;

import jdk.incubator.foreign.CLinker.TypeKind;
import jdk.incubator.foreign.GroupLayout;
import jdk.incubator.foreign.MemoryAddress;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.MemorySegment;
import jdk.incubator.foreign.ValueLayout;
import jdk.internal.foreign.abi.SharedUtils;
import static jdk.incubator.foreign.CLinker.*;
import static jdk.incubator.foreign.CLinker.TypeKind.*;

/**
 * This class enumerates three argument types for Linux/ppc64le, in which case the code
 * is backported from OpenJDK19 with modifications against the implementation of TypeClass
 * on x64/windows as the template.
 */
public enum TypeClass {
	PRIMITIVE, /* Intended for all primitive types */
	POINTER,
	STRUCT;

	private static String osName = System.getProperty("os.name").toLowerCase();
	/* long long is 64 bits on AIX/ppc64, which is the same as Windows */
	private static ValueLayout longLayout = osName.contains("aix") ? C_LONG_LONG : C_LONG;

	public static VarHandle classifyVarHandle(ValueLayout layout) {
		VarHandle argHandle = null;
		Class<?> carrier = classifyCarrier(layout);

		/* According to the API Spec, all non-long integral types are promoted to long
		 * while a float is promoted to double.
		 */
		if ((carrier == byte.class)
			|| (carrier == short.class)
			|| (carrier == int.class)
			|| (carrier == long.class)
		) {
			argHandle = SharedUtils.vhPrimitiveOrAddress(long.class, longLayout);
		} else if (carrier == float.class) {
			argHandle = SharedUtils.vhPrimitiveOrAddress(double.class, C_DOUBLE);
		} else if ((carrier == double.class)
			|| (carrier == MemoryAddress.class)
		) {
			argHandle = SharedUtils.vhPrimitiveOrAddress(carrier, layout);
		} else {
			throw new IllegalStateException("Unspported carrier: " + carrier.getName());
		}

		return argHandle;
	}

	public static Class<?> classifyCarrier(MemoryLayout layout) {
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

	public static TypeClass classifyLayout(MemoryLayout layout) {
		TypeClass layoutType = PRIMITIVE;

		if (layout instanceof ValueLayout) {
			layoutType = classifyValueType((ValueLayout)layout);
		} else if (layout instanceof GroupLayout) {
			layoutType = STRUCT;
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
		case LONG_LONG:   /* Fall through */
		case FLOAT:       /* Fall through */
		case DOUBLE:
			layoutType = PRIMITIVE;
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
