/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.LegacyPropertiesSecurityRealm;
import org.wildfly.security.auth.server.SecurityRealm;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.createTestServer;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a properties file.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PropertiesSecurityRealmTest extends AbstractAuthenticationSuite {

    @BeforeSuite
    public static void setup() throws Exception {
        registerProvider();
        setMode("PROPERTIES");

        Set<String> supportedMechanims = new HashSet<>();
        Collections.addAll(supportedMechanims, "PLAIN");

        createTestServer(PropertiesSecurityRealmTest::createSecurityRealm,
                Collections.unmodifiableSet(supportedMechanims));
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
}
