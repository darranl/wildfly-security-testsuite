/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.util.EnumSet;
import java.util.Set;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.JaasSecurityRealm;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a JAAS {@code LoginModule}.
 */
public class JaasSecurityRealmTest extends AbstractAuthenticationSuite {

    @BeforeSuite
    public static void setup() throws Exception {
        // Create and local resources needed for the SecurityRealm
        System.setProperty("java.security.auth.login.config", JaasSecurityRealmTest.class.getResource("jaas-login.config").toString());
        // Begin any server processes needed by the realm, either in-vm or test containers.
        //  N/A
        // Register a factory for instantiating a security realm instance.
        //  - In integration testing this last step may be register a utility to define the realm in mgmt.
        register("JAAS", JaasSecurityRealmTest::createSecurityRealm,
                JaasSecurityRealmTest::realmHttpMechanisms,
                JaasSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() {
        // Stop any server processes created for the realm either in-vm or test containers.
        // Clean up any filesystem resources for this realm.
        System.clearProperty("java.security.auth.login.config");

        // This impl was in memory so garbage collection is sufficient.
        register(null, null, null, null);
    }

    static SecurityRealm createSecurityRealm() {
        return new JaasSecurityRealm("JaasEntry");
    }

    static Set<SaslAuthenticationMechanism> realmSaslMechanisms() {
        return EnumSet.of(SaslAuthenticationMechanism.PLAIN);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
