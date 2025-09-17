/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.LegacyPropertiesSecurityRealm;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a properties file.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PropertiesSecurityRealmTest extends AbstractAuthenticationSuite {

    @BeforeSuite
    public static void beginRealm() {
        // Create and local resources needed for the SecurityRealm
        //  N/A
        // Begin any server processes needed by the realm, either in-vm or test containers.
        //  N/A
        // Register a factory for instantiating a security realm instance.
        //  - In integration testing this last step may be register a utility to define the realm in mgmt.
        register("Properties", PropertiesSecurityRealmTest::createSecurityRealm,
                PropertiesSecurityRealmTest::realmHttpMechanisms,
                PropertiesSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() {
        // Stop any server processes created for the realm either in-vm or test containers.
        // Clean up any filesystem resources for this realm.

        // This impl was in memory so garbage collection is sufficient.
        register(null, null, null, null);
    }

    static SecurityRealm createSecurityRealm() {
        StringBuilder identitiesString = new StringBuilder();
        obtainTestIdentities().forEach(identity -> {
            identitiesString.append(String.format("%s=%s\n", identity.username(), identity.password()));
        });
        try {
            LegacyPropertiesSecurityRealm realm = LegacyPropertiesSecurityRealm.builder()
                    .setPlainText(true)
                    .setUsersStream(new ByteArrayInputStream(identitiesString.toString().getBytes()))
                    .build();

            return realm;
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to initialize " + PropertiesSecurityRealmTest.class.getName(), ex);
        }
    }

    static Set<SaslAuthenticationMechanism> realmSaslMechanisms() {
        return EnumSet.of(SaslAuthenticationMechanism.PLAIN,
                SaslAuthenticationMechanism.DIGEST_MD5,
                SaslAuthenticationMechanism.DIGEST_SHA_256,
                SaslAuthenticationMechanism.DIGEST_SHA_384,
                SaslAuthenticationMechanism.DIGEST_SHA,
                SaslAuthenticationMechanism.DIGEST_SHA_512_256,
                SaslAuthenticationMechanism.DIGEST_SHA_512);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.DIGEST_MD5,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
