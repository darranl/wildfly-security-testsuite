/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.extras.creaper.core.online.CliException;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.ldap.LdapService;

/**
 * Variant of the {@code AbstractAuthenticationSuite} to test the LDAP security realm.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LdapSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-ldap-realm";
    private static final String REALM_TYPE = "ldap-realm";

    private static final String DIR_CONTEXT_NAME = "test-dir-context";
    private static final int LDAP_PORT = 11390;
    private static final String SERVER_DN = "uid=server,dc=security,dc=wildfly,dc=org";
    private static final String SERVER_CREDENTIAL = "serverPassword";
    private static final String SEARCH_DN = "dc=security,dc=wildfly,dc=org";
    private static final String RDN_IDENTIFIER = "uid";
    private static final String PASSWORD_ATTRIBUTE = "userPassword";
    private static final Path LDAP_DIR = Paths.get("tests-files").toAbsolutePath()
            .resolve(LdapSecurityRealmTest.class.getSimpleName()).resolve("ldap");
    private static LdapService ldapService;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
              LdapSecurityRealmTest::registerSecurityRealm, LdapSecurityRealmTest::removeSecurityRealm),
         LdapSecurityRealmTest::realmHttpMechanisms, LdapSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        // Step 1 - Start the LDAP Server
        try {
            createLdap();
        } catch (Exception e) {
            throw new IOException("Unable to create the LDAP server.", e);
        }

        // Step 2 - Configure WildFly
        try {
            // Add the dir-context
            String url = String.format("ldap://localhost:%d/", LDAP_PORT);
            managementClient.execute(String.format("/subsystem=elytron/dir-context=%s:add(url=\"%s\", principal=\"%s\", credential-reference={clear-text=\"%s\"})",
                DIR_CONTEXT_NAME, url,SERVER_DN, SERVER_CREDENTIAL)).assertSuccess();

            String searchUrl = """
                /subsystem=elytron/ldap-realm=%s:add(dir-context=%s,
                    identity-mapping={search-base-dn=\"%s\",rdn-identifier=%s,
                        user-password-mapper={from=%s},
                        attribute-mapping=[{filter-base-dn=\"%s\",
                            filter=\"uid={0}\", from=employeeType, to=groups}]
                    })
                """;

            managementClient.execute(String.format(searchUrl, REALM_NAME, DIR_CONTEXT_NAME, SEARCH_DN, RDN_IDENTIFIER, PASSWORD_ATTRIBUTE, SEARCH_DN)).assertSuccess();
        } catch (CliException e) {
            throw new IOException("Unable to register security realm configuration.", e);
        }
    }

    static void removeSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        // Step 1 - Remove WildFly Configuration
        try {
            // Remove the Security Realm
            managementClient.execute(String.format("/subsystem=elytron/ldap-realm=%s:remove", REALM_NAME)).assertSuccess();
            // Remove the dir-context
            managementClient.execute(String.format("/subsystem=elytron/dir-context=%s:remove", DIR_CONTEXT_NAME)).assertSuccess();
        } catch (CliException e) {
            throw new IOException("Unable to remove security realm configuration.", e);
        }


        // Step 2 - Stop the LDAP Server
        if (ldapService != null) {
            ldapService.close();
            ldapService = null;
        }
    }

    private static void createLdap() throws Exception {
        // TODO This method was also copied as-us from the unit test, can we move to common?
        StringBuilder identitiesString = new StringBuilder();
        obtainTestIdentities().forEach(identity -> {
            identitiesString.append(String.format("dn: uid=%s,dc=security,dc=wildfly,dc=org\n", identity.username()));
            identitiesString.append("objectClass: top\nobjectClass: inetOrgPerson\nobjectClass: person\nobjectClass: organizationalPerson\n");
            identitiesString.append(String.format("cn: %s\n", identity.username()));
            identitiesString.append(String.format("sn: %s\n", identity.username()));
            identitiesString.append(String.format("uid: %s\n", identity.username()));
            identitiesString.append("employeeType: admin\n");
            identitiesString.append(String.format("userPassword:: %s\n\n", Base64.getEncoder().encodeToString(identity.password().getBytes())));
        });

        ldapService = LdapService.builder()
                .setWorkingDir(LDAP_DIR.toFile())
                .createDirectoryService(LdapSecurityRealmTest.class.getSimpleName())
                .addPartition("Elytron", "dc=security,dc=wildfly,dc=org", 5, "uid")
                .importLdif("ldap-security-realm-test.ldif")
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
                SaslAuthenticationMechanism.DIGEST_SHA_512);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.DIGEST_MD5,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
