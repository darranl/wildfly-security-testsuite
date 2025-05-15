/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;


/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a {@code Map}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class MapSecurityRealmTest extends AbstractAuthenticationSuite {

    private static PasswordFactory passwordFactory;
    @BeforeSuite
    public static void setup() throws Exception {
        // Step 0 - Pre-Initialisation
        passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, TEST_PROVIDERS);

        setMode("MAP");
        // Step 1 - Configured additional required servers.
        // (Not needed for Map as in-memory)

        // Step 2 - Initialise the SecurityDomain
        SecurityDomain securityDomain = createSecurityDomain(MapSecurityRealmTest::createSecurityRealm);

        // Step 3 - Initialise the HTTP process(es)
        // Can we do path based?

        // Step 4 - Initialise the Remoting Connectors
        // Make authentication swappable or should a single connector support all mechs?

        // Can we get all modes available for a single server process?
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

}
