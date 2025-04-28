/*
 * Copyright (c) 2009, 2021, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2022, 2024 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.math.BigInteger;
import java.security.ProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.AlgorithmParameters;
import sun.security.util.CurveDB;
import sun.security.util.NamedCurve;

import jdk.crypto.jniprovider.NativeCrypto;

/**
 * Utility methods for the native EC implementation.
 */
public final class NativeECUtil {

    private static NativeCrypto nativeCrypto;
    private static final boolean nativeCryptTrace = NativeCrypto.isTraceEnabled();

    /* false if OPENSSL_NO_EC2M is defined, true otherwise */
    private static boolean nativeGF2m;

    /* stores whether a curve is supported by OpenSSL (true) or not (false) */
    private static final Map<String, Boolean> curveSupported = new ConcurrentHashMap<>();

    private NativeECUtil() {}

    /**
     * Checks whether the given EC curve is supported by OpenSSL.
     * @param curve the EC curve type
     * @param params the parameters of the EC curve
     * @return true if the curve is supported, false otherwise
     */
    static boolean isCurveSupported(String curve, ECParameterSpec params) {
        if (nativeCrypto == null) {
            nativeCrypto = NativeCrypto.getNativeCrypto();
        }
        nativeGF2m = nativeCrypto.ECNativeGF2m();
        if ((!nativeGF2m) && (params.getCurve().getField() instanceof ECFieldF2m)) {
            boolean absent = NativeECUtil.putCurveIfAbsent("EC2m", Boolean.FALSE);
            if (absent && nativeCryptTrace) {
                System.err.println("EC2m is not supported by OpenSSL, using Java crypto implementation.");
            }
            return false;
        } else {
            return curveSupported.getOrDefault(curve, Boolean.TRUE).booleanValue();
        }
    }

    /**
     * Records whether the specified EC curve is supported by OpenSSL or not,
     * if the curve is not already associated with a value.
     * @param curve the EC curve type
     * @param supported true if the curve is supported by OpenSSL, false otherwise
     * @return true on success (i.e. the curve was not associated with a value), false otherwise
     */
    static boolean putCurveIfAbsent(String curve, Boolean supported) {
        return curveSupported.putIfAbsent(curve, supported) == null;
    }

    /**
     * Returns the EC curve type.
     * @param params the parameters of the EC curve
     * @return the name or OID of the EC curve
     */
    static String getCurveName(ECParameterSpec params) {
        String curveName;
        if (params instanceof NamedCurve namedCurve) {
            curveName = namedCurve.getNameAndAliases()[0];
        } else {
            /* use the OID */
            try {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
                algParams.init(params);
                curveName = algParams.getParameterSpec(ECGenParameterSpec.class).getName();
            } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
                curveName = null;
            }
        }
        return curveName;
    }

    /**
     * Returns the native EC public key context pointer.
     * @param params the parameters of the EC curve
     * @return the native EC key context pointer or -1 on error
     */
    static long encodeGroup(ECParameterSpec params) {
        ECPoint generator = params.getGenerator();
        EllipticCurve curve = params.getCurve();
        ECField field = curve.getField();
        byte[] a = curve.getA().toByteArray();
        byte[] b = curve.getB().toByteArray();
        byte[] gx = generator.getAffineX().toByteArray();
        byte[] gy = generator.getAffineY().toByteArray();
        byte[] n = params.getOrder().toByteArray();
        byte[] h = BigInteger.valueOf(params.getCofactor()).toByteArray();
        int fieldType;
        byte[] p;
        if (field instanceof ECFieldFp ecFieldFp) {
            p = ecFieldFp.getP().toByteArray();
            fieldType = NativeCrypto.ECField_Fp;
        } else if (field instanceof ECFieldF2m ecFieldF2m) {
            p = ecFieldF2m.getReductionPolynomial().toByteArray();
            fieldType = NativeCrypto.ECField_F2m;
        } else {
            return -1;
        }
        if (nativeCrypto == null) {
            nativeCrypto = NativeCrypto.getNativeCrypto();
        }
        return nativeCrypto.ECEncodeGF(fieldType,
                                       a, a.length,
                                       b, b.length,
                                       p, p.length,
                                       gx, gx.length,
                                       gy, gy.length,
                                       n, n.length,
                                       h, h.length);
    }

    /**
     * Returns the native pointer for the provided EC public key.
     *
     * @param key   the EC public key
     * @return      the native EC public key context pointer or -1 on error
     */
    static long getPublicKeyNativePtr(ECPublicKey key) {
        synchronized (key) {
            long nativePointer = encodeGroup(key.getParams());
            if (nativePointer != -1) {
                try {
                    byte[] x = key.getW().getAffineX().toByteArray();
                    byte[] y = key.getW().getAffineY().toByteArray();
                    int fieldType = NativeCrypto.ECField_Fp;
                    if (key.getParams().getCurve().getField() instanceof ECFieldF2m) {
                        fieldType = NativeCrypto.ECField_F2m;
                    }
                    if (nativeCrypto.ECCreatePublicKey(nativePointer, x, x.length, y, y.length, fieldType) == -1) {
                        nativeCrypto.ECDestroyKey(nativePointer);
                        nativePointer = -1;
                    }
                } finally {
                    if (nativePointer != -1) {
                        nativeCrypto.createECKeyCleaner(key, nativePointer);
                    }
                }
            }
            return nativePointer;
        }
    }

    /**
     * Returns the native pointer for the provided EC private key.
     *
     * @param key   the EC private key
     * @return      the native EC private key context pointer or -1 on error
     */
    static long getPrivateKeyNativePtr(ECPrivateKey key) {
        synchronized (key) {
            long nativePointer = encodeGroup(key.getParams());
            if (nativePointer != -1) {
                try {
                    byte[] value = key.getS().toByteArray();
                    if (nativeCrypto.ECCreatePrivateKey(nativePointer, value, value.length) == -1) {
                        nativeCrypto.ECDestroyKey(nativePointer);
                        nativePointer = -1;
                    }
                } finally {
                    if (nativePointer != -1) {
                        nativeCrypto.createECKeyCleaner(key, nativePointer);
                    }
                }
            }
            return nativePointer;
        }
    }

    static boolean isBrainpoolP512r1(ECParameterSpec name) {
        NamedCurve curve = CurveDB.lookup(name);
        if (curve != null) {
            String[] nameAndAliases = curve.getNameAndAliases();
            for (String nameOrAlias : nameAndAliases) {
                if ("brainpoolP512r1".equalsIgnoreCase(nameOrAlias)) {
                    return true;
                }
            }
        }
        return false;
    }
}
