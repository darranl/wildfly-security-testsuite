/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.EnumSet;
import java.util.Set;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.extras.creaper.core.online.CliException;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * Variant of the {@code AbstractAuthenticationSuite} to test the distributed security realm.
 */
public class DistributedSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-distributed-realm";
    private static final String REALM_TYPE = "distributed-realm";
    private static final String TOKEN_REALM_NAME = "test-properties-token-realm";
    private static final String TOKEN_REALM_TYPE = "token-realm";
    private static final String PROPERTIES_REALM_NAME = "test-properties-distributed-realm";
    private static final String PROPERTIES_REALM_TYPE = "properties-realm";

    private static final String PROPERTIES_REALM_USERS_PATH = "test-properties-distributed-realm-users.properties";
    private static final File PROPERTIES_REALM_USERS = SERVER_CONFIG_DIR.resolve(PROPERTIES_REALM_USERS_PATH).toFile();
    private static final String PROPERTIES_REALM_ROLES_PATH = "test-properties-distributed-realm-roles.properties";
    private static final File PROPERTIES_REALM_ROLES = SERVER_CONFIG_DIR.resolve(PROPERTIES_REALM_ROLES_PATH).toFile();

    private volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                        DistributedSecurityRealmTest::registerSecurityRealm, DistributedSecurityRealmTest::removeSecurityRealm),
                DistributedSecurityRealmTest::realmHttpMechanisms,
                DistributedSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        if (PROPERTIES_REALM_USERS.exists()) {
            PROPERTIES_REALM_USERS.delete();
        }
        if (PROPERTIES_REALM_ROLES.exists()) {
            PROPERTIES_REALM_ROLES.delete();
        }

        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try (PrintStream out = new PrintStream(new FileOutputStream(PROPERTIES_REALM_USERS))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), identity.password()));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating users properties file for properties security realm failed: " + ex.getMessage());
        }

        try (PrintStream out = new PrintStream(new FileOutputStream(PROPERTIES_REALM_ROLES))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), "admin"));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating roles properties file for properties security realm failed: " + ex.getMessage());
        }

        try {
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add(jwt={issuer=[\"issuer1.wildfly.org\"]})",
                    TOKEN_REALM_TYPE, TOKEN_REALM_NAME)).assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "users-properties={path=%s, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=%s, relative-to=jboss.server.config.dir})",
                    PROPERTIES_REALM_TYPE, PROPERTIES_REALM_NAME, PROPERTIES_REALM_USERS_PATH, PROPERTIES_REALM_ROLES_PATH))
                    .assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add(realms=[%s,%s])",
                    REALM_TYPE, REALM_NAME, TOKEN_REALM_NAME, PROPERTIES_REALM_NAME)).assertSuccess();
            realmRegistered = true;
        } catch (CliException e) {
            throw new IOException("Unable to register security realm configuration.", e);
        }

    }

    static void removeSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try {
            if (realmRegistered) {
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    REALM_TYPE, REALM_NAME)).assertSuccess();
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    PROPERTIES_REALM_TYPE, PROPERTIES_REALM_NAME)).assertSuccess();
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    TOKEN_REALM_TYPE, TOKEN_REALM_NAME)).assertSuccess();
                realmRegistered = false;
            }
        } catch (CliException e) {
            throw new IOException("Unable to remove security realm configuration.", e);
        }
    }

    static Set<SaslAuthenticationMechanism> realmSaslMechanisms() {
        return EnumSet.of(SaslAuthenticationMechanism.PLAIN,
                SaslAuthenticationMechanism.DIGEST_MD5);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.DIGEST_MD5,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
