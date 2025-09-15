/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.integration.authauthz.runners.BruteForceAuthnProtectionSaslSuiteRunner;
import org.wildfly.security.tests.integration.authauthz.runners.StandardSaslSuiteRunner;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Suite
@SelectClasses(value = { StandardSaslSuiteRunner.class, BruteForceAuthnProtectionSaslSuiteRunner.class })
public abstract class AbstractAuthenticationSuite {

    private static volatile String realmType;
    private static volatile Supplier<String> securityRealmSupplier;
    private static volatile Supplier<Set<HttpAuthenticationMechanism>> supportedHttpAuthenticationMechanisms;
    private static volatile Supplier<Set<SaslAuthenticationMechanism>> supportedSaslAuthenticationMechanisms;

    /*
     * New Registration Methods
     */
    public static void register(String realmType, Supplier<String> securityRealmSupplier,
            Supplier<Set<HttpAuthenticationMechanism>> supportedHttpAuthenticationMechanisms,
            Supplier<Set<SaslAuthenticationMechanism>> supportedSaslAuthenticationMechanisms) {
        AbstractAuthenticationSuite.realmType = realmType;
        AbstractAuthenticationSuite.securityRealmSupplier = securityRealmSupplier;
        AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms = supportedHttpAuthenticationMechanisms;
        AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms = supportedSaslAuthenticationMechanisms;
    }

    public static String realmType() {
        return realmType;
    }

    public static Supplier<String> getSecurityRealmSupplier() {
        return securityRealmSupplier;
    }

    public static Set<HttpAuthenticationMechanism> supportedHttpAuthenticationMechanisms() {
        return supportedHttpAuthenticationMechanisms == null ? Collections.emptySet()
                : supportedHttpAuthenticationMechanisms.get();
    }

    public static Set<SaslAuthenticationMechanism> supportedSaslAuthenticationMechanisms() {
        return supportedSaslAuthenticationMechanisms == null ? Collections.emptySet()
                : supportedSaslAuthenticationMechanisms.get();
    }

    static Stream<IdentityDefinition> obtainTestIdentities() {
        // Register a lot of identities so each test can use it's own without
        // state being contaminated from other tests.
        List<IdentityDefinition> identities = new ArrayList<>(100);
        for (int i = 1 ; i < 100 ; i++) {
            identities.add(new IdentityDefinition(String.format("user%d", i),
                    String.format("password%d", i)));
        }

        return identities.stream();
    }

    record IdentityDefinition(String username, String password) {}
}
