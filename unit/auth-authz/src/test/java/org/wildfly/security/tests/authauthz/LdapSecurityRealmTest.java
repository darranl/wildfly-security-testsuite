/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.ldap.DirContextFactory;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.realm.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by an LDAP.
 */
public class LdapSecurityRealmTest extends AbstractAuthenticationSuite {

    static final String SERVER_DN = "uid=server,dc=security,dc=wildfly,dc=org";
    static final String SERVER_CREDENTIAL = "serverPassword";
    static final int LDAP_PORT = 11390;

    private static final Path LDAP_DIR = Paths.get("tests-files").toAbsolutePath()
            .resolve(LdapSecurityRealmTest.class.getSimpleName()).resolve("ldap");

    private static LdapService ldapService;

    @BeforeSuite
    public static void setup() throws Exception {
        // Begin any server processes needed by the realm, either in-vm or test containers.
        createLdap();
        // Register a factory for instantiating a security realm instance.
        //  - In integration testing this last step may be register a utility to define the realm in mgmt.
        register("LDAP", LdapSecurityRealmTest::createSecurityRealm,
                LdapSecurityRealmTest::realmHttpMechanisms,
                LdapSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        // Stop any server processes created for the realm either in-vm or test containers.
        // Clean up any filesystem resources for this realm.
        ldapService.close();

        // This impl was in memory so garbage collection is sufficient.
        register(null, null, null, null);
    }

    static SecurityRealm createSecurityRealm() {
        LdapSecurityRealmBuilder builder = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(() -> SimpleDirContextFactoryBuilder.builder()
                    .setProviderUrl(String.format("ldap://localhost:%d/", LDAP_PORT))
                    .setSecurityPrincipal(SERVER_DN)
                    .setSecurityCredential(SERVER_CREDENTIAL)
                    .build().obtainDirContext(DirContextFactory.ReferralMode.IGNORE))
                .identityMapping()
                    .setSearchDn("dc=security,dc=wildfly,dc=org")
                    .setRdnIdentifier("uid")
                    .build()
                .userPasswordCredentialLoader().build();
        return builder.build();
    }

    private static void createLdap() throws Exception {
        StringBuilder identitiesString = new StringBuilder();
        obtainTestIdentities().forEach(identity -> {
            identitiesString.append(String.format("dn: uid=%s,dc=security,dc=wildfly,dc=org\n", identity.username()));
            identitiesString.append("objectClass: top\nobjectClass: inetOrgPerson\nobjectClass: person\nobjectClass: organizationalPerson\n");
            identitiesString.append(String.format("cn: %s\n", identity.username()));
            identitiesString.append(String.format("sn: %s\n", identity.username()));
            identitiesString.append(String.format("uid: %s\n", identity.username()));
            identitiesString.append(String.format("userPassword:: %s\n\n", Base64.getEncoder().encodeToString(identity.password().getBytes())));
        });

        ldapService = LdapService.builder()
                .setWorkingDir(LDAP_DIR.toFile())
                .createDirectoryService(LdapSecurityRealmTest.class.getSimpleName())
                .addPartition("Elytron", "dc=security,dc=wildfly,dc=org", 5, "uid")
                .importLdif(LdapSecurityRealmTest.class.getResourceAsStream("ldap-security-realm-test.ldif"))
                .importLdif(new ByteArrayInputStream(identitiesString.toString().getBytes()))
                .addTcpServer("Default TCP", "localhost", LDAP_PORT)
                .start();
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
