/*
 *  Copyright (c) 2020, 2021, Oracle and/or its affiliates. All rights reserved.
 *  DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  This code is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 only, as
 *  published by the Free Software Foundation.  Oracle designates this
 *  particular file as subject to the "Classpath" exception as provided
 *  by Oracle in the LICENSE file that accompanied this code.
 *
 *  This code is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  version 2 for more details (a copy is included in the LICENSE file that
 *  accompanied this code).
 *
 *  You should have received a copy of the GNU General Public License version
 *  2 along with this work; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 *  or visit www.oracle.com if you need additional information or have any
 *  questions.
 *
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2021, 2022 All Rights Reserved
 * ===========================================================================
 */

package jdk.internal.foreign;

import jdk.incubator.foreign.CLinker;
import jdk.incubator.foreign.MemoryLayout;
import jdk.incubator.foreign.ValueLayout;

import java.nio.ByteOrder;

import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.BIG_ENDIAN;

public class PlatformLayouts {
    public static <Z extends MemoryLayout> Z pick(Z sysv, Z win64, Z aarch64, Z sysvppc64le, Z sysvs390x, Z aix) {
        return switch (CABI.current()) {
            case SysV -> sysv;
            case Win64 -> win64;
            case LinuxAArch64, MacOsAArch64 -> aarch64;
            case SysVPPC64le -> sysvppc64le;
            case SysVS390x -> sysvs390x;
            case AIX -> aix;
        };
    }

    public static MemoryLayout asVarArg(MemoryLayout ml) {
        return switch (CABI.current()) {
            case SysV -> SysV.asVarArg(ml);
            case Win64 -> Win64.asVarArg(ml);
            case MacOsAArch64 -> AArch64.asVarArg(ml);
            case SysVPPC64le -> SysVPPC64le.asVarArg(ml);
            case SysVS390x -> SysVS390x.asVarArg(ml);
            case AIX -> AIX.asVarArg(ml);
            default -> ml;
        };
    }

    private static ValueLayout ofChar(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.CHAR);
    }

    private static ValueLayout ofShort(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.SHORT);
    }

    private static ValueLayout ofInt(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.INT);
    }

    private static ValueLayout ofLong(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.LONG);
    }

    private static ValueLayout ofLongLong(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.LONG_LONG);
    }

    private static ValueLayout ofFloat(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.FLOAT);
    }

    private static ValueLayout ofDouble(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.DOUBLE);
    }

    private static ValueLayout ofPointer(ByteOrder order, long bitSize) {
        return MemoryLayout.valueLayout(bitSize, order)
                .withAttribute(CLinker.TypeKind.ATTR_NAME, CLinker.TypeKind.POINTER);
    }

    public static CLinker.TypeKind getKind(MemoryLayout layout) {
        return (CLinker.TypeKind)layout.attribute(CLinker.TypeKind.ATTR_NAME).orElseThrow(
            () -> new IllegalStateException("Unexpected value layout: could not determine ABI class"));
    }

    /**
     * This class defines layout constants modelling standard primitive types supported by the x64 SystemV ABI.
     */
    public static final class SysV {
        private SysV() {
            //just the one
        }

        /**
         * The {@code char} native type.
         */
        public static final ValueLayout C_CHAR = ofChar(LITTLE_ENDIAN, 8);

        /**
         * The {@code short} native type.
         */
        public static final ValueLayout C_SHORT = ofShort(LITTLE_ENDIAN, 16);

        /**
         * The {@code int} native type.
         */
        public static final ValueLayout C_INT = ofInt(LITTLE_ENDIAN, 32);

        /**
         * The {@code long} native type.
         */
        public static final ValueLayout C_LONG = ofLong(LITTLE_ENDIAN, 64);

        /**
         * The {@code long long} native type.
         */
        public static final ValueLayout C_LONG_LONG = ofLongLong(LITTLE_ENDIAN, 64);

        /**
         * The {@code float} native type.
         */
        public static final ValueLayout C_FLOAT = ofFloat(LITTLE_ENDIAN, 32);

        /**
         * The {@code double} native type.
         */
        public static final ValueLayout C_DOUBLE = ofDouble(LITTLE_ENDIAN, 64);

        /**
         * The {@code T*} native type.
         */
        public static final ValueLayout C_POINTER = ofPointer(LITTLE_ENDIAN, 64);

        /**
         * The {@code va_list} native type, as it is passed to a function.
         */
        public static final MemoryLayout C_VA_LIST = SysV.C_POINTER;

        /**
         * The name of the layout attribute (see {@link MemoryLayout#attributes()}) used to mark variadic parameters. The
         * attribute value must be a boolean.
         */
        public static final String VARARGS_ATTRIBUTE_NAME = "abi/sysv/varargs";

        /**
         * Return a new memory layout which describes a variadic parameter to be passed to a function.
         * @param layout the original parameter layout.
         * @return a layout which is the same as {@code layout}, except for the extra attribute {@link #VARARGS_ATTRIBUTE_NAME},
         * which is set to {@code true}.
         */
        public static MemoryLayout asVarArg(MemoryLayout layout) {
            return layout.withAttribute(VARARGS_ATTRIBUTE_NAME, true);
        }
    }

    /**
     * This class defines layout constants modelling standard primitive types supported by the x64 Windows ABI.
     */
    public static final class Win64 {

        private Win64() {
            //just the one
        }

        /**
         * The name of the layout attribute (see {@link MemoryLayout#attributes()}) used to mark variadic parameters. The
         * attribute value must be a boolean.
         */
        public static final String VARARGS_ATTRIBUTE_NAME = "abi/windows/varargs";

        /**
         * The {@code char} native type.
         */
        public static final ValueLayout C_CHAR = ofChar(LITTLE_ENDIAN, 8);

        /**
         * The {@code short} native type.
         */
        public static final ValueLayout C_SHORT = ofShort(LITTLE_ENDIAN, 16);

        /**
         * The {@code int} native type.
         */
        public static final ValueLayout C_INT = ofInt(LITTLE_ENDIAN, 32);
        /**
         * The {@code long} native type.
         */
        public static final ValueLayout C_LONG = ofLong(LITTLE_ENDIAN, 32);

        /**
         * The {@code long long} native type.
         */
        public static final ValueLayout C_LONG_LONG = ofLongLong(LITTLE_ENDIAN, 64);

        /**
         * The {@code float} native type.
         */
        public static final ValueLayout C_FLOAT = ofFloat(LITTLE_ENDIAN, 32);

        /**
         * The {@code double} native type.
         */
        public static final ValueLayout C_DOUBLE = ofDouble(LITTLE_ENDIAN, 64);

        /**
         * The {@code T*} native type.
         */
        public static final ValueLayout C_POINTER = ofPointer(LITTLE_ENDIAN, 64);

        /**
         * The {@code va_list} native type, as it is passed to a function.
         */
        public static final MemoryLayout C_VA_LIST = Win64.C_POINTER;

        /**
         * Return a new memory layout which describes a variadic parameter to be passed to a function.
         * @param layout the original parameter layout.
         * @return a layout which is the same as {@code layout}, except for the extra attribute {@link #VARARGS_ATTRIBUTE_NAME},
         * which is set to {@code true}.
         */
        public static MemoryLayout asVarArg(MemoryLayout layout) {
            return layout.withAttribute(VARARGS_ATTRIBUTE_NAME, true);
        }
    }

    /**
     * This class defines layout constants modelling standard primitive types supported by the AArch64 ABI.
     */
    public static final class AArch64 {

        private AArch64() {
            //just the one
        }

        /**
         * The {@code char} native type.
         */
        public static final ValueLayout C_CHAR = ofChar(LITTLE_ENDIAN, 8);

        /**
         * The {@code short} native type.
         */
        public static final ValueLayout C_SHORT = ofShort(LITTLE_ENDIAN, 16);

        /**
         * The {@code int} native type.
         */
        public static final ValueLayout C_INT = ofInt(LITTLE_ENDIAN, 32);

        /**
         * The {@code long} native type.
         */
        public static final ValueLayout C_LONG = ofLong(LITTLE_ENDIAN, 64);

        /**
         * The {@code long long} native type.
         */
        public static final ValueLayout C_LONG_LONG = ofLongLong(LITTLE_ENDIAN, 64);

        /**
         * The {@code float} native type.
         */
        public static final ValueLayout C_FLOAT = ofFloat(LITTLE_ENDIAN, 32);

        /**
         * The {@code double} native type.
         */
        public static final ValueLayout C_DOUBLE = ofDouble(LITTLE_ENDIAN, 64);

        /**
         * The {@code T*} native type.
         */
        public static final ValueLayout C_POINTER = ofPointer(LITTLE_ENDIAN, 64);

        /**
         * The {@code va_list} native type, as it is passed to a function.
         */
        public static final MemoryLayout C_VA_LIST = AArch64.C_POINTER;

        /**
         * The name of the layout attribute (see {@link MemoryLayout#attributes()})
         * used to mark variadic parameters on systems such as macOS which pass these
         * entirely on the stack. The attribute value must be a boolean.
         */
        public final static String STACK_VARARGS_ATTRIBUTE_NAME = "abi/aarch64/stack_varargs";

        /**
         * Return a new memory layout which describes a variadic parameter to be
         * passed to a function. This is only required on platforms such as macOS
         * which pass variadic parameters entirely on the stack.
         * @param layout the original parameter layout.
         * @return a layout which is the same as {@code layout}, except for
         * the extra attribute {@link #STACK_VARARGS_ATTRIBUTE_NAME}, which is set
         * to {@code true}.
         */
        public static MemoryLayout asVarArg(MemoryLayout layout) {
            return layout.withAttribute(STACK_VARARGS_ATTRIBUTE_NAME, true);
        }
    }

    /**
     * This class defines layout constants modelling standard primitive types supported by the PPC64LE SystemV ABI.
     */
    public static final class SysVPPC64le {
        private SysVPPC64le() {
            //just the one
        }

        /**
         * The {@code char} native type.
         */
        public static final ValueLayout C_CHAR = ofChar(LITTLE_ENDIAN, 8);

        /**
         * The {@code short} native type.
         */
        public static final ValueLayout C_SHORT = ofShort(LITTLE_ENDIAN, 16);

        /**
         * The {@code int} native type.
         */
        public static final ValueLayout C_INT = ofInt(LITTLE_ENDIAN, 32);

        /**
         * The {@code long} native type.
         */
        public static final ValueLayout C_LONG = ofLong(LITTLE_ENDIAN, 64);

        /**
         * The {@code long long} native type.
         */
        public static final ValueLayout C_LONG_LONG = ofLongLong(LITTLE_ENDIAN, 64);

        /**
         * The {@code float} native type.
         */
        public static final ValueLayout C_FLOAT = ofFloat(LITTLE_ENDIAN, 32);

        /**
         * The {@code double} native type.
         */
        public static final ValueLayout C_DOUBLE = ofDouble(LITTLE_ENDIAN, 64);

        /**
         * The {@code T*} native type.
         */
        public static final ValueLayout C_POINTER = ofPointer(LITTLE_ENDIAN, 64);

        /**
         * The {@code va_list} native type, as it is passed to a function.
         */
        public static final MemoryLayout C_VA_LIST = SysVPPC64le.C_POINTER;

        /**
         * The name of the layout attribute (see {@link MemoryLayout#attributes()}) used to mark variadic parameters. The
         * attribute value must be a boolean.
         */
        public static final String VARARGS_ATTRIBUTE_NAME = "abi/ppc64/sysv/varargs";

        /**
         * Return a new memory layout which describes a variadic parameter to be passed to a function.
         * @param layout the original parameter layout.
         * @return a layout which is the same as {@code layout}, except for the extra attribute {@link #VARARGS_ATTRIBUTE_NAME},
         * which is set to {@code true}.
         */
        public static MemoryLayout asVarArg(MemoryLayout layout) {
            return layout.withAttribute(VARARGS_ATTRIBUTE_NAME, true);
        }
    }

    /**
     * This class defines layout constants modelling standard primitive types supported by the s390x SystemV ABI.
     */
    public static final class SysVS390x {
        private SysVS390x() {
            //just the one
        }

        /**
         * The {@code char} native type.
         */
        public static final ValueLayout C_CHAR = ofChar(BIG_ENDIAN, 8);

        /**
         * The {@code short} native type.
         */
        public static final ValueLayout C_SHORT = ofShort(BIG_ENDIAN, 16);

        /**
         * The {@code int} native type.
         */
        public static final ValueLayout C_INT = ofInt(BIG_ENDIAN, 32);

        /**
         * The {@code long} native type.
         */
        public static final ValueLayout C_LONG = ofLong(BIG_ENDIAN, 64);

        /**
         * The {@code long long} native type.
         */
        public static final ValueLayout C_LONG_LONG = ofLongLong(BIG_ENDIAN, 64);

        /**
         * The {@code float} native type.
         */
        public static final ValueLayout C_FLOAT = ofFloat(BIG_ENDIAN, 32);

        /**
         * The {@code double} native type.
         */
        public static final ValueLayout C_DOUBLE = ofDouble(BIG_ENDIAN, 64);

        /**
         * The {@code T*} native type.
         */
        public static final ValueLayout C_POINTER = ofPointer(BIG_ENDIAN, 64);

        /**
         * The {@code va_list} native type, as it is passed to a function.
         */
        public static final MemoryLayout C_VA_LIST = SysVS390x.C_POINTER;

        /**
         * The name of the layout attribute (see {@link MemoryLayout#attributes()}) used to mark variadic parameters. The
         * attribute value must be a boolean.
         */
        public static final String VARARGS_ATTRIBUTE_NAME = "abi/s390x/sysv/varargs";

        /**
         * Return a new memory layout which describes a variadic parameter to be passed to a function.
         * @param layout the original parameter layout.
         * @return a layout which is the same as {@code layout}, except for the extra attribute {@link #VARARGS_ATTRIBUTE_NAME},
         * which is set to {@code true}.
         */
        public static MemoryLayout asVarArg(MemoryLayout layout) {
            return layout.withAttribute(VARARGS_ATTRIBUTE_NAME, true);
        }
    }

    /**
     * This class defines layout constants modelling standard primitive types supported by the AIX PPC64 C ABI.
     */
    public static final class AIX {
        private AIX() {
            //just the one
        }

        /**
         * The {@code char} native type.
         */
        public static final ValueLayout C_CHAR = ofChar(BIG_ENDIAN, 8);

        /**
         * The {@code short} native type.
         */
        public static final ValueLayout C_SHORT = ofShort(BIG_ENDIAN, 16);

        /**
         * The {@code int} native type.
         */
        public static final ValueLayout C_INT = ofInt(BIG_ENDIAN, 32);

        /**
         * The {@code long} native type.
         */
        public static final ValueLayout C_LONG = ofLong(BIG_ENDIAN, 32);

        /**
         * The {@code long long} native type.
         */
        public static final ValueLayout C_LONG_LONG = ofLongLong(BIG_ENDIAN, 64).withBitAlignment(32);

        /**
         * The {@code float} native type.
         */
        public static final ValueLayout C_FLOAT = ofFloat(BIG_ENDIAN, 32);

        /**
         * The {@code double} native type.
         */
        public static final ValueLayout C_DOUBLE = ofDouble(BIG_ENDIAN, 64).withBitAlignment(32);

        /**
         * The {@code T*} native type.
         */
        public static final ValueLayout C_POINTER = ofPointer(BIG_ENDIAN, 64).withBitAlignment(32);

        /**
         * The {@code va_list} native type, as it is passed to a function.
         */
        public static final MemoryLayout C_VA_LIST = AIX.C_POINTER;

        /**
         * The name of the layout attribute (see {@link MemoryLayout#attributes()}) used to mark variadic parameters. The
         * attribute value must be a boolean.
         */
        public static final String VARARGS_ATTRIBUTE_NAME = "abi/ppc64/aix/varargs";

        /**
         * Return a new memory layout which describes a variadic parameter to be passed to a function.
         * @param layout the original parameter layout.
         * @return a layout which is the same as {@code layout}, except for the extra attribute {@link #VARARGS_ATTRIBUTE_NAME},
         * which is set to {@code true}.
         */
        public static MemoryLayout asVarArg(MemoryLayout layout) {
            return layout.withAttribute(VARARGS_ATTRIBUTE_NAME, true);
        }
    }
}
