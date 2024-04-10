/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2024 All Rights Reserved
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
package openj9.internal.security;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider.Service;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import sun.security.util.Debug;

/**
 * Configures the security providers when in restricted security mode.
 */
public final class RestrictedSecurity {

    private static final Debug debug = Debug.getInstance("semerufips");

    // Restricted security mode enable check.
    private static final boolean userEnabledFIPS;
    private static boolean isFIPSSupported;
    private static boolean isFIPSEnabled;

    private static final boolean allowSetProperties;

    private static final boolean isNSSSupported;
    private static final boolean isOpenJCEPlusSupported;

    private static final boolean userSetProfile;
    private static final boolean shouldEnableSecurity;
    private static String selectedProfile;
    private static String profileID;

    private static boolean securityEnabled;

    private static String userSecurityID;

    private static RestrictedSecurityProperties restricts;

    private static final Set<String> unmodifiableProperties = new HashSet<>();

    private static final Map<String, List<String>> supportedPlatformsNSS = new HashMap<>();
    private static final Map<String, List<String>> supportedPlatformsOpenJCEPlus = new HashMap<>();

    static {
        supportedPlatformsNSS.put("Arch", List.of("amd64", "ppc64le", "s390x"));
        supportedPlatformsNSS.put("OS", List.of("Linux"));

        supportedPlatformsOpenJCEPlus.put("Arch", List.of("amd64", "ppc64", "s390x"));
        supportedPlatformsOpenJCEPlus.put("OS", List.of("Linux", "AIX", "Windows"));

        @SuppressWarnings("removal")
        String[] props = AccessController.doPrivileged(
                new PrivilegedAction<>() {
                    @Override
                    public String[] run() {
                        return new String[] { System.getProperty("semeru.fips"),
                                System.getProperty("semeru.customprofile"),
                                System.getProperty("os.name"),
                                System.getProperty("os.arch"),
                                System.getProperty("semeru.fips.allowsetproperties") };
                    }
                });

        boolean isOsSupported, isArchSupported;
        // Check whether the NSS FIPS solution is supported.
        isOsSupported = false;
        for (String os: supportedPlatformsNSS.get("OS")) {
            if (props[2].contains(os)) {
                isOsSupported = true;
            }
        }
        isArchSupported = false;
        for (String arch: supportedPlatformsNSS.get("Arch")) {
            if (props[3].contains(arch)) {
                isArchSupported = true;
            }
        }
        isNSSSupported = isOsSupported && isArchSupported;

        // Check whether the OpenJCEPlus FIPS solution is supported.
        isOsSupported = false;
        for (String os: supportedPlatformsOpenJCEPlus.get("OS")) {
            if (props[2].contains(os)) {
                isOsSupported = true;
            }
        }
        isArchSupported = false;
        for (String arch: supportedPlatformsOpenJCEPlus.get("Arch")) {
            if (props[3].contains(arch)) {
                isArchSupported = true;
            }
        }
        isOpenJCEPlusSupported = isOsSupported && isArchSupported;

        // Check the default solution to see if FIPS is supported.
        isFIPSSupported = isNSSSupported;

        userEnabledFIPS = Boolean.parseBoolean(props[0]);
        allowSetProperties = Boolean.parseBoolean(props[4]);

        if (userEnabledFIPS) {
            if (isFIPSSupported) {
                // Set to default profile for the default FIPS solution.
                selectedProfile = "NSS.140-2";
            }
        }

        // If user has specified a profile, use that
        if (props[1] != null) {
            selectedProfile = props[1];
            userSetProfile = true;
        } else {
            userSetProfile = false;
        }

        // Check if FIPS is supported on this platform without explicitly setting a profile.
        if (userEnabledFIPS && !isFIPSSupported && !userSetProfile) {
            printStackTraceAndExit("FIPS mode is not supported on this platform by default.\n"
                    + " Use the semeru.customprofile system property to use an available FIPS-compliant profile.\n"
                    + " Note: Not all platforms support FIPS at the moment.");
        }

        shouldEnableSecurity = (userEnabledFIPS && isFIPSSupported) || userSetProfile;
    }

    private RestrictedSecurity() {
        super();
    }

    /**
     * Check if restricted security mode is enabled.
     *
     * Restricted security mode is enabled when, on supported platforms,
     * the semeru.customprofile system property is used to set a
     * specific security profile or the semeru.fips system property is
     * set to true.
     *
     * @return true if restricted security mode is enabled
     */
    public static boolean isEnabled() {
        return securityEnabled;
    }

    /**
     * Get restricted security mode secure random provider.
     *
     * Restricted security mode secure random provider can only
     * be called in restricted security mode.
     *
     * @return the secure random provider
     */
    public static String getRandomProvider() {
        if (!securityEnabled) {
            printStackTraceAndExit(
                    "Restricted security mode secure random provider can only be used when restricted security mode is enabled.");
        }
        return restricts.getProperty("jdkSecureRandomProvider");
    }

    /**
     * Get restricted security mode secure random algorithm.
     *
     * Restricted security mode secure random algorithm can only
     * be called in restricted security mode.
     *
     * @return the secure random algorithm
     */
    public static String getRandomAlgorithm() {
        if (!securityEnabled) {
            printStackTraceAndExit(
                    "Restricted security mode secure random algorithm can only be used when restricted security mode is enabled.");
        }
        return restricts.getProperty("jdkSecureRandomAlgorithm");
    }

    /**
     * Check if the FIPS mode is enabled.
     *
     * FIPS mode will be enabled when the semeru.fips system property is
     * true, and the RestrictedSecurity mode has been successfully initialized.
     *
     * @return true if FIPS is enabled
     */
    public static boolean isFIPSEnabled() {
        if (securityEnabled) {
            return isFIPSEnabled;
        }
        return false;
    }

    /**
     * Check if the service is allowed in restricted security mode.
     *
     * @param service the service to check
     * @return true if the service is allowed
     */
    public static boolean isServiceAllowed(Service service) {
        if (securityEnabled) {
            return restricts.isRestrictedServiceAllowed(service);
        }
        return true;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerName the provider to check
     * @return true if the provider is allowed
     */
    public static boolean isProviderAllowed(String providerName) {
        if (securityEnabled) {
            return restricts.isRestrictedProviderAllowed(providerName);
        }
        return true;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerClazz the provider class to check
     * @return true if the provider is allowed
     */
    public static boolean isProviderAllowed(Class<?> providerClazz) {
        if (securityEnabled) {
            String providerName = providerClazz.getName();

            // Check if the specified class extends java.security.Provider.
            if (java.security.Provider.class.isAssignableFrom(providerClazz)) {
                return restricts.isRestrictedProviderAllowed(providerName);
            }

            // For a class that doesn't extend java.security.Provider, no need to
            // check allowed or not allowed, always return true to load it.
            if (debug != null) {
                debug.println("The provider class " + providerName + " does not extend java.security.Provider.");
            }
        }
        return true;
    }

    /**
     * Figure out the full profile ID.
     *
     * Use the default or user selected profile and attempt to find
     * an appropriate entry in the java.security properties.
     *
     * If a profile cannot be found, or multiple defaults are discovered
     * for a single profile, an appropriate message is printed and the
     * system exits.
     *
     * @param props the java.security properties
     */
    private static void getProfileID(Properties props) {
        String potentialProfileID = "RestrictedSecurity." + selectedProfile;

        if (selectedProfile.indexOf(".") != -1) {
            /* The default profile is used, or the user specified the
             * full <profile.version>.
             */
            if (debug != null) {
                debug.println("Profile specified using full name (i.e., <profile.version>): "
                        + selectedProfile);
            }
            for (Object keyObject : props.keySet()) {
                if (keyObject instanceof String key) {
                    if (key.startsWith(potentialProfileID)) {
                        profileID = potentialProfileID;
                        return;
                    }
                }
            }
            printStackTraceAndExit(selectedProfile + " is not present in the java.security file.");
        } else {
            /* The user specified the only the <profile> without
             * indicating the <version> part.
             */
            if (debug != null) {
                debug.println("Profile specified without version (i.e., <profile>): "
                        + selectedProfile);
            }
            String defaultMatch = null;
            for (Object keyObject : props.keySet()) {
                if (keyObject instanceof String key) {
                    if (key.startsWith(potentialProfileID) && key.endsWith(".desc.default")) {
                        // Check if property is set to true.
                        if (Boolean.parseBoolean(props.getProperty(key))) {
                            // Check if multiple defaults exist and act accordingly.
                            if (defaultMatch == null) {
                                defaultMatch = key.split("\\.desc")[0];
                            } else {
                                printStackTraceAndExit("Multiple default RestrictedSecurity"
                                        + " profiles for " + selectedProfile);
                            }
                        }
                    }
                }
            }
            if (defaultMatch == null) {
                printStackTraceAndExit("No default RestrictedSecurity profile was found for "
                        + selectedProfile);
            } else {
                profileID = defaultMatch;
            }
        }
    }

    private static void checkIfKnownProfileSupported() {
        if (profileID.contains("NSS") && !isNSSSupported) {
            printStackTraceAndExit("NSS RestrictedSecurity profiles are not supported"
                    + " on this platform.");
        }

        if (profileID.contains("OpenJCEPlus") && !isOpenJCEPlusSupported) {
            printStackTraceAndExit("OpenJCEPlus RestrictedSecurity profiles are not supported"
                    + " on this platform.");
        }

        if (debug != null) {
            debug.println("RestrictedSecurity profile " + profileID
                    + " is supported on this platform.");
        }
    }

    private static void checkFIPSCompatibility() {
        boolean isFIPSProfile = restricts.descIsFIPS;
        if (isFIPSProfile) {
            if (debug != null) {
                debug.println("RestrictedSecurity profile " + profileID
                        + " is specified as FIPS compliant.");
            }
            isFIPSEnabled = true;
        } else {
            printStackTraceAndExit("RestrictedSecurity profile " + profileID
                    + " is not specified as FIPS compliant, but the semeru.fips"
                    + " system property is set to true.");
        }
    }

    /**
     * Check whether a security property can be set.
     *
     * A security property that is set by a RestrictedSecurity profile,
     * while FIPS security mode is enabled, cannot be reset programmatically.
     *
     * Every time an attempt to set a security property is made, a check is
     * performed. If the above scenario holds true, a SecurityException is
     * thrown.
     *
     * One can override this behaviour and allow the user to set any security
     * property through the use of {@code -Dsemeru.fips.allowsetproperties=true}.
     *
     * @param key the security property that the user wants to set
     * @throws SecurityException
     *         if the security property is set by the profile and cannot
     *         be altered
     */
    public static void checkSetSecurityProperty(String key) {
        if (debug != null) {
            debug.println("RestrictedSecurity: Checking whether property '"
                    + key + "' can be set.");
        }

        /*
         * Only disallow setting of security properties that are set by the active profile,
         * if FIPS has been enabled.
         *
         * Allow any change, if the 'semeru.fips.allowsetproperties' flag is set to true.
         */
        if (unmodifiableProperties.contains(key)) {
            if (debug != null) {
                debug.println("RestrictedSecurity: Property '" + key + "' cannot be set.");
                debug.println("If you want to override the check and allow all security"
                        + "properties to be set, use '-Dsemeru.fips.allowsetproperties=true'.");
                debug.println("BEWARE: You might not be FIPS compliant if you select to override!");
            }
            throw new SecurityException("FIPS mode: User-specified '" + key
                    + "' cannot override profile definition.");
        }

        if (debug != null) {
            debug.println("RestrictedSecurity: Property '"
                    + key + "' can be set without issue.");
        }
    }

    /**
     * Remove the security providers and only add restricted security providers.
     *
     * @param props the java.security properties
     * @return true if restricted security properties loaded successfully
     */
    public static boolean configure(Properties props) {
        // Check if restricted security is already initialized.
        if (securityEnabled) {
            printStackTraceAndExit("Restricted security mode is already initialized, it can't be initialized twice.");
        }

        try {
            if (shouldEnableSecurity) {
                if (debug != null) {
                    debug.println("Restricted security mode is being enabled...");
                }

                getProfileID(props);
                checkIfKnownProfileSupported();

                // Initialize restricted security properties from java.security file.
                restricts = new RestrictedSecurityProperties(profileID, props);

                // Restricted security properties checks.
                restrictsCheck();

                // Remove all security providers.
                for (Iterator<Map.Entry<Object, Object>> i = props.entrySet().iterator(); i.hasNext();) {
                    Map.Entry<Object, Object> e = i.next();
                    String key = (String) e.getKey();
                    if (key.startsWith("security.provider")) {
                        if (debug != null) {
                            debug.println("Removing provider: " + e);
                        }
                        i.remove();
                    }
                }

                // Add restricted security providers.
                setProviders(props);

                // Add restricted security Properties.
                setProperties(props);

                if (debug != null) {
                    debug.println("Restricted security mode loaded.");
                    debug.println("Restricted security mode properties: " + props.toString());
                }

                securityEnabled = true;
            }
        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to load restricted security mode configurations.");
            }
            printStackTraceAndExit(e);
        }
        return securityEnabled;
    }

    /**
     * Add restricted security providers.
     *
     * @param props the java.security properties
     */
    private static void setProviders(Properties props) {
        if (debug != null) {
            debug.println("Adding restricted security provider.");
        }

        int pNum = 0;
        for (String provider : restricts.providers) {
            pNum += 1;
            props.setProperty("security.provider." + pNum, provider);
            if (debug != null) {
                debug.println("Added restricted security provider: " + provider);
            }
        }
    }

    /**
     * Add restricted security properties.
     *
     * @param props the java.security properties
     */
    private static void setProperties(Properties props) {
        if (debug != null) {
            debug.println("Adding restricted security properties.");
        }

        Map<String, String> propsMapping = new HashMap<>();

        // JDK properties name as key, restricted security properties value as value.
        propsMapping.put("jdk.tls.disabledNamedCurves", restricts.getProperty("jdkTlsDisabledNamedCurves"));
        propsMapping.put("jdk.tls.disabledAlgorithms", restricts.getProperty("jdkTlsDisabledAlgorithms"));
        propsMapping.put("jdk.tls.ephemeralDHKeySize", restricts.getProperty("jdkTlsEphemeralDHKeySize"));
        propsMapping.put("jdk.tls.legacyAlgorithms", restricts.getProperty("jdkTlsLegacyAlgorithms"));
        propsMapping.put("jdk.certpath.disabledAlgorithms", restricts.getProperty("jdkCertpathDisabledAlgorithms"));
        propsMapping.put("jdk.security.legacyAlgorithms", restricts.getProperty("jdkSecurityLegacyAlgorithms"));
        String fipsMode = System.getProperty("com.ibm.fips.mode");
        if (fipsMode == null) {
            System.setProperty("com.ibm.fips.mode", restricts.getProperty("jdkFipsMode"));
        } else if (!fipsMode.equals(restricts.getProperty("jdkFipsMode"))) {
            printStackTraceAndExit("Property com.ibm.fips.mode is incompatible with semeru.customprofile and semeru.fips properties");
        }

        for (Map.Entry<String, String> entry : propsMapping.entrySet()) {
            String jdkPropsName = entry.getKey();
            String propsNewValue = entry.getValue();

            if ((propsNewValue != null) && userEnabledFIPS && !allowSetProperties) {
                // Add to set of properties set by the active profile.
                unmodifiableProperties.add(jdkPropsName);
            }

            if (!isNullOrBlank(propsNewValue)) {
                props.setProperty(jdkPropsName, propsNewValue);
                if (debug != null) {
                    debug.println("Added restricted security properties, with property: "
                            + jdkPropsName + " value: " + propsNewValue);
                }
            }
        }

        // For keyStore and keystore.type, old value not needed, just set the new value.
        String keyStoreType = restricts.getProperty("keyStoreType");
        if (!isNullOrBlank(keyStoreType)) {
            props.setProperty("keystore.type", keyStoreType);
        }
        String keyStore = restricts.getProperty("keyStore");
        if (!isNullOrBlank(keyStore)) {
            // SSL property "javax.net.ssl.keyStore" set at the JVM level via system properties.
            System.setProperty("javax.net.ssl.keyStore", keyStore);
        }
    }

    /**
     * Check restricted security properties.
     */
    private static void restrictsCheck() {
        // Check restricts object.
        if (restricts == null) {
            printStackTraceAndExit("Restricted security property is null.");
        }

        // Check if the SunsetDate expired.
        if (isPolicySunset(restricts.getProperty("descSunsetDate"))) {
            printStackTraceAndExit("Restricted security policy expired.");
        }

        // Check secure random settings.
        if (isNullOrBlank(restricts.getProperty("jdkSecureRandomProvider"))
                || isNullOrBlank(restricts.getProperty("jdkSecureRandomAlgorithm"))) {
            printStackTraceAndExit("Restricted security mode secure random is missing.");
        }

        // If user enabled FIPS, check whether chosen profile is applicable.
        if (userEnabledFIPS) {
            checkFIPSCompatibility();
        }
    }

    /**
     * Check if restricted security policy is sunset.
     *
     * @param descSunsetDate the sunset date from java.security
     * @return true if restricted security policy sunset
     */
    private static boolean isPolicySunset(String descSunsetDate) {
        boolean isSunset = false;
        // Only check if a sunset date is specified in the profile.
        if (!isNullOrBlank(descSunsetDate)) {
            try {
                isSunset = LocalDate.parse(descSunsetDate, DateTimeFormatter.ofPattern("yyyy-MM-dd"))
                        .isBefore(LocalDate.now());
            } catch (DateTimeParseException except) {
                printStackTraceAndExit(
                        "Restricted security policy sunset date is incorrect, the correct format is yyyy-MM-dd.");
            }
        }

        if (debug != null) {
            debug.println("Restricted security policy is sunset: " + isSunset);
        }
        return isSunset;
    }

    /**
     * Check if the input string is null or blank.
     *
     * @param string the input string
     * @return true if the input string is null or blank
     */
    private static boolean isNullOrBlank(String string) {
        return (string == null) || string.isBlank();
    }

    private static void printStackTraceAndExit(Exception exception) {
        exception.printStackTrace();
        System.exit(1);
    }

    private static void printStackTraceAndExit(String message) {
        printStackTraceAndExit(new RuntimeException(message));
    }

    /**
     * This class is used to save and operate on restricted security
     * properties which are loaded from the java.security file.
     */
    private static final class RestrictedSecurityProperties {
        // Properties specified through the profile.
        private final Map<String, String> profileProperties;
        private boolean descIsDefault;
        private boolean descIsFIPS;

        // Provider with argument (provider name + optional argument).
        private final List<String> providers;
        // Provider without argument.
        private final List<String> providersSimpleName;
        // The map is keyed by provider name.
        private final Map<String, List<Constraint>> providerConstraints;

        private final String profileID;

        // The java.security properties.
        private final Properties securityProps;

        private final List<String> appendableProps = Arrays.asList("jdkTlsDisabledNamedCurves",
                                                                   "jdkTlsDisabledAlgorithms",
                                                                   "jdkTlsLegacyAlgorithms",
                                                                   "jdkCertpathDisabledAlgorithms",
                                                                   "jdkSecurityLegacyAlgorithms");

        /**
         *
         * @param id    the restricted security custom profile ID
         * @param props the java.security properties
         * @param trace the user security trace
         * @param audit the user security audit
         * @param help  the user security help
         */
        private RestrictedSecurityProperties(String id, Properties props) {
            Objects.requireNonNull(props);

            profileID = id;
            securityProps = props;

            profileProperties = new HashMap<>();

            providers = new ArrayList<>();
            providersSimpleName = new ArrayList<>();
            providerConstraints = new HashMap<>();

            // Initialize the properties.
            init(profileID);

            if (debug != null) {
                // Print information of utilized security profile.
                listUsedProfile(profileID);
            }
        }

        /**
         * Initialize restricted security properties.
         */
        private void init(String profileID) {
            if (debug != null) {
                debug.println("Initializing restricted security properties for '" + profileID + "'.");
            }

            String potentialExtendsProfileID = parseProperty(securityProps.getProperty(profileID + ".extends"));
            if (potentialExtendsProfileID != null) { // If profile extends another profile.
                if (debug != null) {
                    debug.println("\t'" + profileID + "' extends '" + potentialExtendsProfileID + "'.");
                }

                // Check if extended profile exists.
                String extendsProfileID = null;
                if (potentialExtendsProfileID.indexOf(".") != potentialExtendsProfileID.lastIndexOf(".")) {
                    // Extended profile id has at least 2 dots (meaning it's a full profile id).
                    for (Object keyObject : securityProps.keySet()) {
                        if (keyObject instanceof String key) {
                            if (key.startsWith(potentialExtendsProfileID + ".desc") ||
                                key.startsWith(potentialExtendsProfileID + ".fips") ||
                                key.startsWith(potentialExtendsProfileID + ".tls") ||
                                key.startsWith(potentialExtendsProfileID + ".jce") ||
                                key.startsWith(potentialExtendsProfileID + ".javax") ||
                                key.startsWith(potentialExtendsProfileID + ".securerandom")
                            ) {
                                // If even one security property is found for this profile id, move on.
                                extendsProfileID = potentialExtendsProfileID;
                                break;
                            }
                        }
                    }
                    if (extendsProfileID == null) {
                        printStackTraceAndExit(potentialExtendsProfileID + " that is supposed to extend '"
                                + profileID + "'is not present in the java.security file or any appended files.");
                    }
                }

                // Recursively call init() on extended profile.
                init(potentialExtendsProfileID);

                // Perform update based on current profile.
                update(profileID);
            } else {
                try {
                    // Load restricted security providers from java.security properties.
                    initProviders(profileID);
                    // Load restricted security properties from java.security properties.
                    initProperties(profileID);
                    // Load restricted security provider constraints from java.security properties.
                    //initConstraints(profileID);
                } catch (Exception e) {
                    if (debug != null) {
                        debug.println("Unable to initialize restricted security mode.");
                    }
                    printStackTraceAndExit(e);
                }
            }

            if (debug != null) {
                debug.println("Initialization of restricted security properties for '" + profileID + "' completed.");

                
            }
        }

        /**
         * Initialize restricted security properties.
         */
        private void update(String profileExtensionId) {
            try {
                // Load restricted security providers from java.security properties.
                updateProviders(profileExtensionId);
                // Load restricted security properties from java.security properties.
                initProperties(profileExtensionId);
                // Load restricted security provider constraints from java.security properties.
                //updateConstraints(profileExtensionId, updatedProvidersPosition);
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("Unable to update restricted security properties for '" + profileExtensionId + "'.");
                }
                printStackTraceAndExit(e);
            }
        }

        private void parseProvider(String providerInfo, int providerPos, boolean update) {
            // if (!areBracketsBalanced(providerInfo)) {
            //     printStackTraceAndExit("Provider format is incorrect: " + providerInfo);
            // }
            if (debug != null) {
                debug.println("\t\tLoading provider in position " + providerPos);
            }

            checkProviderFormat(providerInfo, update);

            int pos = providerInfo.indexOf('[');
            String providerName = (pos < 0) ? providerInfo.trim() : providerInfo.substring(0, pos).trim();
            // Provider with argument (provider name + optional argument).
            if (update) {
                providers.set(providerPos - 1, providerName);
            } else {
                providers.add(providerPos - 1, providerName);
            }

            // Remove the provider's optional arguments if there are.
            pos = providerName.indexOf(' ');
            if (pos >= 0) {
                providerName = providerName.substring(0, pos);
            }
            providerName = providerName.trim();

            // Remove argument, e.g. -NSS-FIPS, if present.
            pos = providerName.indexOf('-');
            if (pos >= 0) {
                providerName = providerName.substring(0, pos);
            }

            // Provider name defined in provider construction method.
            providerName = getProvidersSimpleName(providerName);
            boolean providerChanged = false;
            if (update) {
                String previousProviderName = providersSimpleName.get(providerPos - 1);
                providerChanged = !previousProviderName.equals(providerName);
                providersSimpleName.set(providerPos - 1, providerName);
            } else {
                providersSimpleName.add(providerPos - 1, providerName);
            }

            if (debug != null) {
                debug.println("\t\tLoaded provider in position " + providerPos + " named: " + providerName);
            }

            setConstraints(providerName, providerInfo, providerChanged);
        }

        private void removeProvider(String profileExtensionId, int providerPos) {
            if (debug != null) {
                debug.println("\t\tRemoving provider in position " + providerPos);
            }

            int numOfExistingProviders = providersSimpleName.size();

            // This is the last provider.
            if (providerPos == numOfExistingProviders) {
                if (debug != null) {
                    debug.println("\t\t\tLast provider. Only one to be removed.");
                }
                String providerRemoved = providersSimpleName.remove(providerPos - 1);
                providers.remove(providerPos - 1);
                providerConstraints.remove(providerRemoved);

                if (debug != null) {
                    debug.println("\t\tProvider " + providerRemoved + " removed.");
                }
                return;
            }

            // If there's more, check that all of them are set to be removed.
            for (int i = numOfExistingProviders; i >= providerPos; i--) {
                if (debug != null) {
                    debug.println("\t\t\tNot the last provider. More to be removed.");
                }

                String providerInfo = securityProps.getProperty(profileExtensionId + ".jce.provider." + i);
                if ((providerInfo == null) || !providerInfo.trim().isEmpty()) {
                    printStackTraceAndExit(
                        "Cannot specify an empty provider in position "
                                + providerPos + " without empty the ones after it.");
                }

                String providerRemoved = providersSimpleName.remove(i - 1);
                providers.remove(i - 1);
                providerConstraints.remove(providerRemoved);

                if (debug != null) {
                    debug.println("\t\tProvider " + providerRemoved + " removed.");
                }
            }
        }

        /**
         * Load restricted security provider.
         */
        private void initProviders(String profileID) {
            if (debug != null) {
                debug.println("\tLoading providers of restricted security profile.");
            }

            for (int pNum = 1;; ++pNum) {
                String property = profileID + ".jce.provider." + pNum;
                String providerInfo = securityProps.getProperty(property);

                if (providerInfo == null) {
                    break;
                }

                if (providerInfo.trim().isEmpty()) {
                    printStackTraceAndExit(
                        "Cannot specify an empty provider in position "
                                + pNum + ". Nothing specified before.");
                }

                parseProvider(providerInfo, pNum, false);
            }

            if (providers.isEmpty()) {
                printStackTraceAndExit(
                        "No providers are specified as part of the Restricted Security profile.");
            }

            if (debug != null) {
                debug.println("\tProviders of restricted security profile successfully loaded.");
            }
        }

        private void updateProviders(String profileExtensionId) {
            int posOfRemovedProvider = -1;
            int numOfExistingProviders = providersSimpleName.size();
            // Deal with update of existing providers.
            for (int i = 1; i <= numOfExistingProviders; i++) {
                String providerInfo = securityProps.getProperty(profileExtensionId + ".jce.provider." + i);

                // TODO: Can one set to empty to remove?
                if (providerInfo != null) {
                    if (!providerInfo.trim().isEmpty()) {
                        parseProvider(providerInfo, i, true);
                    } else {
                        // Remove provider after checking.
                        removeProvider(profileExtensionId, i);
                        posOfRemovedProvider = i;
                    }
                }
            }

            // Deal with additional providers added.
            for (int i = numOfExistingProviders + 1;; i++) {
                String providerInfo = securityProps
                        .getProperty(profileExtensionId + ".jce.provider." + i);

                if (providerInfo == null) {
                    break;
                }

                if (providerInfo.trim().isEmpty()) {
                    printStackTraceAndExit(
                        "Cannot specify an empty provider in position "
                            + i + ". Nothing specified before.");
                }

                if (posOfRemovedProvider != -1) {
                    printStackTraceAndExit(
                        "Cannot add a provider in position " + i
                            + " after removing the one is position " + posOfRemovedProvider + ".");
                }

                parseProvider(providerInfo, i, false);
            }
        }

        /**
         * Load restricted security properties.
         */
        private void initProperties(String profileID) {
            if (debug != null) {
                debug.println("\tLoading properties of restricted security profile.");
            }

            setProperty("descName", securityProps.getProperty(profileID + ".desc.name"));
            if (setProperty("descIsDefaultString", securityProps.getProperty(profileID + ".desc.default"))) {
                descIsDefault = Boolean.parseBoolean(profileProperties.get("descIsDefaultString"));
            }
            if (setProperty("descIsFIPSString", securityProps.getProperty(profileID + ".desc.fips"))) {
                descIsFIPS = Boolean.parseBoolean(profileProperties.get("descIsFIPSString"));
            }
            setProperty("descNumber", securityProps.getProperty(profileID + ".desc.number"));
            setProperty("descPolicy", securityProps.getProperty(profileID + ".desc.policy"));
            setProperty("descSunsetDate", securityProps.getProperty(profileID + ".desc.sunsetDate"));

            setProperty("jdkTlsDisabledNamedCurves",
                    securityProps.getProperty(profileID + ".tls.disabledNamedCurves"));
            setProperty("jdkTlsDisabledAlgorithms",
                    securityProps.getProperty(profileID + ".tls.disabledAlgorithms"));
            setProperty("jdkTlsEphemeralDHKeySize",
                    securityProps.getProperty(profileID + ".tls.ephemeralDHKeySize"));
            setProperty("jdkTlsLegacyAlgorithms",
                    securityProps.getProperty(profileID + ".tls.legacyAlgorithms"));
            setProperty("jdkCertpathDisabledAlgorithms",
                    securityProps.getProperty(profileID + ".jce.certpath.disabledAlgorithms"));
            setProperty("jdkSecurityLegacyAlgorithms",
                    securityProps.getProperty(profileID + ".jce.legacyAlgorithms"));
            setProperty("keyStoreType",
                    securityProps.getProperty(profileID + ".keystore.type"));
            setProperty("keyStore",
                    securityProps.getProperty(profileID + ".javax.net.ssl.keyStore"));

            setProperty("jdkSecureRandomProvider",
                    securityProps.getProperty(profileID + ".securerandom.provider"));
            setProperty("jdkSecureRandomAlgorithm",
                    securityProps.getProperty(profileID + ".securerandom.algorithm"));
            setProperty("jdkFipsMode",
                    securityProps.getProperty(profileID + ".fips.mode"));

            if (debug != null) {
                debug.println("\tProperties of restricted security profile successfully loaded.");
            }
        }

        private void setConstraints(String providerName, String providerInfo, boolean providerChanged) {
            if (debug != null) {
                debug.println("\t\tLoading constraints for security provider: " + providerName);
            }

            List<Constraint> constraints = new ArrayList<>();

            providerInfo = providerInfo.replaceAll("\\s+", "");

            Pattern p = Pattern.compile("\\[.+\\]");
            Matcher m = p.matcher(providerInfo);
            if (!m.find()) {
                if (debug != null) {
                    debug.println("\t\t\tNo constraints for security provider: " + providerName);
                }
                providerConstraints.put(providerName, constraints);
                return;
            }

            p = Pattern.compile(
"\\[([\\+\\-]?)(\\{\\w+,[A-Za-z0-9\\.]+,[A-Za-z0-9\\=\\*:]+\\})(,\\{\\w+,[A-Za-z0-9\\.]+,[A-Za-z0-9\\=\\*:]+\\})*\\]");
            m = p.matcher(providerInfo);

            if (!m.find()) {
                printStackTraceAndExit("Incorrect constraint definition for provider " + providerName);
            }

            String action = m.group(1);

            p = Pattern.compile("\\{(\\w+),([A-Za-z0-9\\.]+),([A-Za-z0-9\\=\\*:]+)\\}");
            m = p.matcher(providerInfo);
            
            while (m.find()) {
                String inType = m.group(1);
                String inAlgorithm = m.group(2);
                String inAttributes = m.group(3);

                // Each attribute must includes 2 fields (key and value) or *.
                if (!isAsterisk(inAttributes)) {
                    String[] attributeArray = inAttributes.split(":");
                    for (String attribute : attributeArray) {
                        String[] in = attribute.split("=", 2);
                        if (in.length != 2) {
                            printStackTraceAndExit(
                                    "Constraint attributes format is incorrect: " + providerInfo);
                        }
                    }
                }
                Constraint constraint = new Constraint(inType, inAlgorithm, inAttributes);
                constraints.add(constraint);
            }

            // Differeriante between add, remove and override.
            if (!isNullOrBlank(action)) {
                if (providerChanged) {
                    printStackTraceAndExit(
                        "Cannot append or remove constraints since the provider " + providerName
                        + " wasn't in this position in the profile extended.");
                }
                List<Constraint> existingConstraints = providerConstraints.get(providerName);
                if (existingConstraints == null) {
                    existingConstraints = new ArrayList<>();
                    providerConstraints.put(providerName, existingConstraints);
                }
                if (action.equals("+")) { // Appending constraints.
                    existingConstraints.addAll(constraints);
                } else { // Removing constraints.
                    for (Constraint toRemove: constraints) {
                        if (!existingConstraints.remove(toRemove)) {
                            printStackTraceAndExit(
                                    "Constraint " + toRemove + "is not part of existing constraints.");
                        }
                    }
                }
            } else {
                providerConstraints.put(providerName, constraints);
            }

            if (debug != null) {
                debug.println("\t\t\tSuccessfully loaded constraints for security provider: " + providerName);
            }
        }

        /**
         * Check if the Service is allowed in restricted security mode.
         *
         * @param service the Service to check
         * @return true if the Service is allowed
         */
        boolean isRestrictedServiceAllowed(Service service) {
            String providerName = service.getProvider().getName();

            // Provider with argument, remove argument.
            // e.g. SunPKCS11-NSS-FIPS, remove argument -NSS-FIPS.
            int pos = providerName.indexOf('-');
            providerName = (pos < 0) ? providerName : providerName.substring(0, pos);

            List<Constraint> constraints = providerConstraints.get(providerName);

            if (constraints == null) {
                // Disallow unknown providers.
                return false;
            } else if (constraints.isEmpty()) {
                // Allow this provider with no constraints.
                return true;
            }

            // Check the constraints of this provider.
            String type = service.getType();
            String algorithm = service.getAlgorithm();

            for (Constraint constraint : constraints) {
                String cType = constraint.type;
                String cAlgorithm = constraint.algorithm;
                String cAttribute = constraint.attributes;

                if (!isAsterisk(cType) && !type.equals(cType)) {
                    // The constraint doesn't apply to the service type.
                    continue;
                }
                if (!isAsterisk(cAlgorithm) && !algorithm.equalsIgnoreCase(cAlgorithm)) {
                    // The constraint doesn't apply to the service algorith.
                    continue;
                }

                // For type and algorithm match, and attribute is *.
                if (isAsterisk(cAttribute)) {
                    if (debug != null) {
                        debug.println("Security constraints check."
                                + " Service type: " + type
                                + " Algorithm: " + algorithm
                                + " is allowed in provider " + providerName);
                    }
                    return true;
                }

                // For type and algorithm match, and attribute is not *.
                // Then continue checking attributes.
                String[] cAttributeArray = cAttribute.split(":");

                // For each attribute, must be all matched for return allowed.
                for (String attribute : cAttributeArray) {
                    String[] input = attribute.split("=", 2);

                    String cName = input[0].trim();
                    String cValue = input[1].trim();
                    String sValue = service.getAttribute(cName);
                    if ((sValue == null) || !cValue.equalsIgnoreCase(sValue)) {
                        // If any attribute doesn't match, return service is not allowed.
                        if (debug != null) {
                            debug.println(
                                    "Security constraints check."
                                            + " Service type: " + type
                                            + " Algorithm: " + algorithm
                                            + " Attribute: " + cAttribute
                                            + " is NOT allowed in provider: " + providerName);
                        }
                        return false;
                    }
                }
                if (debug != null) {
                    debug.println(
                            "Security constraints check."
                                    + " Service type: " + type
                                    + " Algorithm: " + algorithm
                                    + " Attribute: " + cAttribute
                                    + " is allowed in provider: " + providerName);
                }
                return true;
            }
            if (debug != null) {
                debug.println("Security constraints check."
                        + " Service type: " + type
                        + " Algorithm: " + algorithm
                        + " is NOT allowed in provider " + providerName);
            }
            // No match for any constraint, return NOT allowed.
            return false;
        }

        /**
         * Check if the provider is allowed in restricted security mode.
         *
         * @param providerName the provider to check
         * @return true if the provider is allowed
         */
        boolean isRestrictedProviderAllowed(String providerName) {
            if (debug != null) {
                debug.println("Checking the provider " + providerName + " in restricted security mode.");
            }

            // Remove argument, e.g. -NSS-FIPS, if there is.
            int pos = providerName.indexOf('-');
            if (pos >= 0) {
                providerName = providerName.substring(0, pos);
            }

            // Provider name defined in provider construction method.
            providerName = getProvidersSimpleName(providerName);

            // Check if the provider is in restricted security provider list.
            // If not, the provider won't be registered.
            if (providersSimpleName.contains(providerName)) {
                if (debug != null) {
                    debug.println("The provider " + providerName + " is allowed in restricted security mode.");
                }
                return true;
            }

            if (debug != null) {
                debug.println("The provider " + providerName + " is not allowed in restricted security mode.");

                debug.println("Stack trace:");
                StackTraceElement[] elements = Thread.currentThread().getStackTrace();
                for (int i = 1; i < elements.length; i++) {
                    StackTraceElement stack = elements[i];
                    debug.println("\tat " + stack.getClassName() + "." + stack.getMethodName() + "("
                            + stack.getFileName() + ":" + stack.getLineNumber() + ")");
                }
            }
            return false;
        }

        /**
         * Get the provider name defined in provider construction method.
         *
         * @param providerName provider name or provider with packages
         * @return provider name defined in provider construction method
         */
        private static String getProvidersSimpleName(String providerName) {
            if (providerName.equals("com.sun.security.sasl.Provider")) {
                // The main class for the SunSASL provider is com.sun.security.sasl.Provider.
                return "SunSASL";
            } else {
                // Remove the provider's class package names if present.
                int pos = providerName.lastIndexOf('.');
                if (pos >= 0) {
                    providerName = providerName.substring(pos + 1);
                }
                // Provider without package names.
                return providerName;
            }
        }

        /**
         * List audit info of all available RestrictedSecurity profiles.
         */
        private void listAvailableProfiles() {
            System.out.println();
            System.out.println("Restricted Security Available Profiles' Info:");
            System.out.println("=============================================");

            Set<String> availableProfiles = new HashSet<>();
            Pattern profileNamePattern = Pattern.compile("^(RestrictedSecurity\\.\\S+)\\.desc\\.name");
            for(Object securityFileObject : securityProps.keySet()) {
                if (securityFileObject instanceof String key) {
                    Matcher profileMatcher = profileNamePattern.matcher(key);
                    if (profileMatcher.matches()) {
                        availableProfiles.add(profileMatcher.group(1));
                    }
                }
            }
            System.out.println("The available Restricted Security profiles:\n");

            for (String availableProfile : availableProfiles) {
                printProfile(availableProfile);
            }
        }

        /**
         * List the RestrictedSecurity profile currently used.
         */
        private void listUsedProfile(String profileID) {
            System.out.println();
            System.out.println("Utilized Restricted Security Profile Info:");
            System.out.println("==========================================");
            System.out.println("The Restricted Security profile used is: " + profileID);
            System.out.println();
            System.out.println(profileID + " Profile Info:");
            System.out.println("==========================================");
            printProperty(profileID + ".desc.name: ", profileProperties.get("descName"));
            printProperty(profileID + ".desc.default: ", profileProperties.get("descIsDefaultString"));
            printProperty(profileID + ".desc.fips: ", profileProperties.get("descIsFIPSString"));
            printProperty(profileID + ".fips.mode: ", profileProperties.get("jdkFipsMode"));
            printProperty(profileID + ".desc.number: ", profileProperties.get("descNumber"));
            printProperty(profileID + ".desc.policy: ", profileProperties.get("descPolicy"));
            printProperty(profileID + ".desc.sunsetDate: ", profileProperties.get("descSunsetDate"));
            System.out.println();

            // List providers.
            System.out.println(profileID + " Profile Providers:");
            System.out.println("===============================================");
            for (int providerPosition = 0; providerPosition < providers.size(); providerPosition++) {
                printProperty(profileID + ".jce.provider." + (providerPosition + 1) + ": ",
                        providers.get(providerPosition));
                String providerSimpleName = providersSimpleName.get(providerPosition);
                for (Constraint providerConstraint: providerConstraints.get(providerSimpleName)) {
                    System.out.println("\t" + providerConstraint.toString());
                }
            }
            System.out.println();

            // List profile restrictions.
            System.out.println(profileID + " Profile Restrictions:");
            System.out.println("==================================================");
            printProperty(profileID + ".tls.disabledNamedCurves: ", profileProperties.get("jdkTlsDisabledNamedCurves"));
            printProperty(profileID + ".tls.disabledAlgorithms: ", profileProperties.get("jdkTlsDisabledAlgorithms"));
            printProperty(profileID + ".tls.ephemeralDHKeySize: ", profileProperties.get("jdkTlsEphemeralDHKeySize"));
            printProperty(profileID + ".tls.legacyAlgorithms: ", profileProperties.get("jdkTlsLegacyAlgorithms"));
            printProperty(profileID + ".jce.certpath.disabledAlgorithms: ", profileProperties.get("jdkCertpathDisabledAlgorithms"));
            printProperty(profileID + ".jce.legacyAlgorithms: ", profileProperties.get("jdkSecurityLegacyAlgorithms"));
            System.out.println();

            printProperty(profileID + ".keystore.type: ", profileProperties.get("keyStoreType"));
            printProperty(profileID + ".javax.net.ssl.keyStore: ", profileProperties.get("keyStore"));
            printProperty(profileID + ".securerandom.provider: ", profileProperties.get("jdkSecureRandomProvider"));
            printProperty(profileID + ".securerandom.algorithm: ", profileProperties.get("jdkSecureRandomAlgorithm"));
            System.out.println();
        }

        private void printProfile(String profileToPrint) {
            Set<String> propertyNames = securityProps.stringPropertyNames();
            List<String> descKeys = new ArrayList<>();
            List<String> providers = new ArrayList<>();
            List<String> restrictions = new ArrayList<>();
            for (String propertyName : propertyNames) {
                if (propertyName.startsWith(profileToPrint + ".desc.") || propertyName.startsWith(profileToPrint + ".fips.")) {
                    descKeys.add(propertyName + securityProps.getProperty(propertyName));
                } else if (propertyName.startsWith(profileToPrint + ".jce.provider.")) {
                    providers.add(propertyName + securityProps.getProperty(propertyName));
                } else if (propertyName.startsWith(profileToPrint)) {
                    restrictions.add(propertyName + securityProps.getProperty(propertyName));
                }

            }

            System.out.println(profileToPrint + " Profile Info:");
            System.out.println("==========================================");
            for (String descKey : descKeys) {
                System.out.println(descKey);
            }
            System.out.println();

            // List providers.
            System.out.println(profileToPrint + " Profile Providers:");
            System.out.println("===============================================");
            for (String provider : providers) {
                System.out.println(provider);
            }
            System.out.println();

            // List profile restrictions.
            System.out.println(profileToPrint + " Profile Restrictions:");
            System.out.println("==================================================");
            for (String restriction : restrictions) {
                System.out.println(restriction);
            }
            System.out.println();
        }

        private static void printProperty(String name, String value) {
            if (value != null) {
                String valueToPrint = (value.isEmpty()) ? "EMPTY" : value;
                System.out.println(name + valueToPrint);
            } else if (debug != null) {
                debug.println("Nothing to print. Value of property " + name + " is null.");
            }
        }

        /**
         * Only set a property if the value is not null.
         *
         * @param property  the property to be set
         * @param value     the value to check and set the property to
         * @return          whether the property was set
         */
        private boolean setProperty(String property, String value) {
            if (debug != null) {
                debug.println("Setting property: " + property);
            }
            value = parseProperty(value);
            String newValue = null;
            if (value != null) {
                // Check if property overrides, adds to or removes from previous value.
                String existingValue = profileProperties.get(property);
                if (!value.isBlank() && value.startsWith("+")) {
                    if (isPropertyAppendable(property)) {
                        // Append additional values to property.
                        value = value.substring(1, value.length()).trim();

                        // Take existing value of property into account, if applicable.
                        if (existingValue == null) {
                            printStackTraceAndExit("Property '" + property + "' does not exist in parent profile. Cannot append.");
                        } else if (existingValue.isBlank()) {
                            newValue = value;
                        } else {
                            newValue = (value.isBlank()) ? existingValue : existingValue + ", " + value;
                        }
                    } else {
                        printStackTraceAndExit("Property '" + property + "' is not appendable.");
                    }
                } else if (!value.isBlank() && value.startsWith("-")) {
                    if (isPropertyAppendable(property)) {
                        // Remove values from property.
                        value = value.substring(1, value.length()).trim();
                        if (!value.isBlank()) {
                            List<String> existingValues = Arrays.asList(existingValue.split(","));
                            existingValues = existingValues.stream().map(v -> v.trim()).collect(Collectors.toList());
                            List<String> valuesToRemove = Arrays.asList(value.split(","));
                            for (String valueToRemove : valuesToRemove) {
                                if (existingValues.contains(valueToRemove.trim())) {
                                    existingValues.remove(valueToRemove.trim());
                                } else {
                                    printStackTraceAndExit("Value '" + valueToRemove + "' is not in existing values.");
                                }
                            }
                            newValue = String.join(",", existingValues);
                        } else {
                            // Nothing to do. Use existing value of property into account, if available.
                            if (existingValue == null) {
                                printStackTraceAndExit("Property '" + property + "' does not exist in parent profile. Cannot remove.");
                            } else if (existingValue.isBlank()) {
                                newValue = value;
                            } else {
                                newValue = existingValue;
                            }
                        }
                    } else {
                        printStackTraceAndExit("Property '" + property + "' is not appendable.");
                    }
                } else {
                    newValue = value;
                }
                profileProperties.put(property, newValue);
                return true;
            }
            if (debug != null) {
                debug.println("Nothing to set. Value of property " + property + " is null.");
            }

            return false;
        }

        private String getProperty(String property) {
            return profileProperties.get(property);
        }

        private boolean isPropertyAppendable(String property) {
            return appendableProps.contains(property);
        }

        /**
         * Trim input string if not null.
         *
         * @param string the input string
         * @return the string trimmed or null
         */
        private static String parseProperty(String string) {
            if (string != null) {
                string = string.trim();
            }

            return string;
        }

        private static void checkProviderFormat(String providerInfo, boolean update) {
            Pattern p = Pattern.compile(
    "^([A-Za-z0-9\\-\\.]+)\\s*(\\s[A-Za-z0-9\\$\\{\\}\\./]+)?\\s*(\\s\\[([\\+\\-])?([A-Za-z0-9\\{\\}\\.\\=\\*:,\\s]+)\\])?\\s*$");
            Matcher m = p.matcher(providerInfo);
            if (m.find()) {
                String symbol = m.group(4);
                if (!update && (symbol != null)) {
                    printStackTraceAndExit("You cannot add or remove to provider "
                            + m.group(1) + ". This is the base profile.");
                }
            } else {
                printStackTraceAndExit("Provider format is incorrect: " + providerInfo);
            }
        }


        /**
         * Check if the brackets are balanced.
         *
         * @param string input string for checking
         * @return true if the brackets are balanced
         */
        private static boolean areBracketsBalanced(String string) {
            Deque<Character> deque = new LinkedList<>();

            for (char ch : string.toCharArray()) {
                switch (ch) {
                case '{':
                    deque.addFirst('}');
                    break;
                case '[':
                    deque.addFirst(']');
                    break;
                case '(':
                    deque.addFirst(')');
                    break;
                case '}':
                case ']':
                case ')':
                    if (deque.isEmpty() || (deque.removeFirst().charValue() != ch)) {
                        return false;
                    }
                    break;
                default:
                    break;
                }
            }
            return deque.isEmpty();
        }

        /**
         * Check if the input string is asterisk (*).
         *
         * @param string input string for checking
         * @return true if the input string is asterisk
         */
        private static boolean isAsterisk(String string) {
            return "*".equals(string);
        }

        /**
         * A class representing the constraints of a provider.
         */
        private static final class Constraint {
            final String type;
            final String algorithm;
            final String attributes;

            Constraint(String type, String algorithm, String attributes) {
                super();
                this.type = type;
                this.algorithm = algorithm;
                this.attributes = attributes;
            }

            @Override
            public String toString() {
                return "{" + type + ", " + algorithm + ", " + attributes + "}";
            }

            @Override
            public boolean equals(Object obj) {
                if (this == obj)
                    return true;
                if (obj == null)
                    return false;
                if (getClass() != obj.getClass())
                    return false;
                Constraint other = (Constraint) obj;
                if (type == null) {
                    if (other.type != null)
                        return false;
                } else if (!type.equals(other.type))
                    return false;
                if (algorithm == null) {
                    if (other.algorithm != null)
                        return false;
                } else if (!algorithm.equals(other.algorithm))
                    return false;
                if (attributes == null) {
                    if (other.attributes != null)
                        return false;
                } else if (!attributes.equals(other.attributes))
                    return false;
                return true;
            }

            
        }
    }
}
