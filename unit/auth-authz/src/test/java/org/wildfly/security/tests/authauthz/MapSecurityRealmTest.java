/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;


/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a {@code Map}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class MapSecurityRealmTest extends AbstractAuthenticationSuite {

    private static PasswordFactory passwordFactory;

    @BeforeSuite
    public static void setup() throws Exception {
        // Create and local resources needed for the SecurityRealm
        registerProvider();
        passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, TEST_PROVIDERS);
        // Begin any server processes needed by the realm, either in-vm or test containers.
        //  N/A
        // Register a factory for instantiating a security realm instance.
        //  - In integration testing this last step may be register a utility to define the realm in mgmt.
        register("Map", MapSecurityRealmTest::createSecurityRealm,
                MapSecurityRealmTest::realmHttpMechanisms,
                MapSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() {
        // Stop any server processes created for the realm either in-vm or test containers.
        // Clean up any filesystem resources for this realm.

        // This impl was in memory so garbage collection is sufficient.
        register(null, null, null, null);
    }

    static SecurityRealm createSecurityRealm() {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm(TEST_PROVIDERS);

        realm.setIdentityMap(obtainTestIdentities().collect(
                Collectors.toMap(IdentityDefinition::username,
                        i -> {
                            List<Credential> credentials =
                                    Collections.singletonList(new PasswordCredential(toPassword(i.password())));

                            return new SimpleRealmEntry(credentials, Attributes.EMPTY);
                        }
        )));

        return realm;
    }

    static Password toPassword(final String password) {
        try {
            return passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray()));
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
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
