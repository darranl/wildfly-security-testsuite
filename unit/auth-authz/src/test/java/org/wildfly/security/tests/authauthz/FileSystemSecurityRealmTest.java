/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.TEST_PROVIDERS;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.createTestServer;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by file system.
 */
public class FileSystemSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final Path REALM_DIR = Paths.get("tests-files").toAbsolutePath()
            .resolve(FileSystemSecurityRealmTest.class.getSimpleName());

    private static PasswordFactory passwordFactory;

    @BeforeSuite
    public static void setup() throws Exception {
        registerProvider();
        passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, TEST_PROVIDERS);
        setMode("FILESYSTEM");

        Set<String> supportedMechanims = new HashSet<>();
        Collections.addAll(supportedMechanims, "PLAIN");

        createTestServer(FileSystemSecurityRealmTest::createSecurityRealm,
                Collections.unmodifiableSet(supportedMechanims));
    }

    static SecurityRealm createSecurityRealm() {
        FileSystemSecurityRealm realm = FileSystemSecurityRealm.builder()
                .setRoot(REALM_DIR)
                .build();

        obtainTestIdentities().forEach(identity -> {
            ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(identity.username()));
            try {
                realmIdentity.create();
                realmIdentity.setCredentials(Collections.singleton(new PasswordCredential(toPassword(identity.password()))));
                realmIdentity.dispose();
            } catch (RealmUnavailableException ex) {
                throw new IllegalStateException("Unable to initialize " + FileSystemSecurityRealmTest.class.getName(), ex);
            }
        });

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
