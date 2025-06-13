/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.createTestServer;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.JaasSecurityRealm;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a JAAS {@code LoginModule}.
 */
public class JaasSecurityRealmTest extends AbstractAuthenticationSuite {

    @BeforeSuite
    public static void setup() throws Exception {
        System.setProperty("java.security.auth.login.config", JaasSecurityRealmTest.class.getResource("jaas-login.config").toString());
        registerProvider();
        setMode("JAAS");

        Set<String> supportedMechanims = new HashSet<>();
        Collections.addAll(supportedMechanims, "PLAIN");

        createTestServer(JaasSecurityRealmTest::createSecurityRealm,
                Collections.unmodifiableSet(supportedMechanims));
    }

    @AfterSuite
    public static void cleanup() {
        System.clearProperty("java.security.auth.login.config");
    }

    static SecurityRealm createSecurityRealm() {
        return new JaasSecurityRealm("JaasEntry");
    }
}
