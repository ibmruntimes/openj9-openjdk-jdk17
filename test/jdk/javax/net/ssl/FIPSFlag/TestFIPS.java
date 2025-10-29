/*
 * Copyright (c) 2010, 2016, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

import java.security.Provider;
import java.security.Security;

public class TestFIPS {

    private static final String SEMERU_FIPS = System.getProperty("semeru.fips");
    private static final String PROFILE = System.getProperty("semeru.customprofile");

    public static void main(String[] args) throws Exception {

        for (Provider.Service service : Security.getProvider("SUN").getServices()) {
            System.out.println("Service: " + service.getType() + " Algorithm: " + service.getAlgorithm() + " Class: " + service.getClassName());
        }

        if (SEMERU_FIPS == null) {
            if (args[0].equals("false")) {
                System.out.println("PASS");
            } else {
                throw new FIPSException("FIPS mode should be opened before using.");
            }
            return;
        }

        if (PROFILE == null) {
            if (SEMERU_FIPS.equals(args[0])) {
                if (args[0].equals("true")) {
                    if (System.getProperty("com.ibm.fips.mode").equals("140-2") && args[1].equals("140-2")) {
                        System.out.println("PASS");
                    } else {
                        throw new FIPSException("If there is no custom profile specified, the FIPS 140-2 should be used as default.");
                    }
                } else {
                    throw new FIPSException("FIPS mode is not opened.");
                }
            } else {
                throw new FIPSException("FIPS mode and expected mode do not match.");
            }
            return;
        }

        System.out.println("profile is: " + PROFILE);
        if (PROFILE.contains("OpenJCEPlusFIPS")) {
            if (SEMERU_FIPS.equals(args[0])) {
                if (args[0].equals("true")) {
                    if (System.getProperty("com.ibm.fips.mode").equals("140-3") && args[1].equals("140-3")) {
                        System.out.println("PASS");
                    } else {
                        throw new FIPSException("FIPS profile and fips mode do not match.");
                    }
                } else {
                    throw new FIPSException("FIPS mode is not opened.");
                }
            }
        } else {
            throw new FIPSException("FIPS profile is not supported in FIPS 140-3 mode.");
        }
    }

    public static class FIPSException extends Exception {
        public FIPSException(String message) {
            super(message);
        }
    }
}
