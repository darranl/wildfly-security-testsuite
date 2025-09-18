/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.platform.suite.api.AfterSuite;

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
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by file system.
 */
public class FileSystemSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final Path REALM_DIR = Paths.get("tests-files").toAbsolutePath()
            .resolve(FileSystemSecurityRealmTest.class.getSimpleName());

    private static PasswordFactory passwordFactory;

    @BeforeSuite
    public static void setup() throws Exception {
        // Create and local resources needed for the SecurityRealm
        passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, TEST_PROVIDERS);
         // Begin any server processes needed by the realm, either in-vm or test containers.
        //  N/A
        // Register a factory for instantiating a security realm instance.
        //  - In integration testing this last step may be register a utility to define the realm in mgmt.
        register("FileSystem", FileSystemSecurityRealmTest::createSecurityRealm,
                FileSystemSecurityRealmTest::realmHttpMechanisms,
                FileSystemSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        // Stop any server processes created for the realm either in-vm or test containers.
        // Clean up any filesystem resources for this realm.
        try (Stream<Path> pathStream = Files.walk(REALM_DIR)) {
            pathStream.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
        }

        // This impl was in memory so garbage collection is sufficient.
        register(null, null, null, null);
    }

    static SecurityRealm createSecurityRealm() {
        FileSystemSecurityRealm realm = FileSystemSecurityRealm.builder()
                .setRoot(REALM_DIR)
                .build();

        if (!Files.exists(REALM_DIR)) {
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
        }

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
