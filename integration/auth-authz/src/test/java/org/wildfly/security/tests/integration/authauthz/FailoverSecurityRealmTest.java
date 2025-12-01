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
 * Variant of the {@code AbstractAuthenticationSuite} to test the failover security realm.
 */
public class FailoverSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-failover-realm";
    private static final String REALM_TYPE = "failover-realm";
    private static final String DELEGATE_REALM_NAME = "test-jdbc-failover-realm";
    private static final String DELEGATE_REALM_TYPE = "jdbc-realm";
    private static final String FAILOVER_REALM_NAME = "test-properties-failover-realm";
    private static final String FAILOVER_REALM_TYPE = "properties-realm";

    private static final String FAILOVER_REALM_USERS_PATH = "test-properties-failover-realm-users.properties";
    private static final File FAILOVER_REALM_USERS = SERVER_CONFIG_DIR.resolve(FAILOVER_REALM_USERS_PATH).toFile();
    private static final String FAILOVER_REALM_ROLES_PATH = "test-properties-failover-realm-roles.properties";
    private static final File FAILOVER_REALM_ROLES = SERVER_CONFIG_DIR.resolve(FAILOVER_REALM_ROLES_PATH).toFile();

    private volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                                            FailoverSecurityRealmTest::registerSecurityRealm, FailoverSecurityRealmTest::removeSecurityRealm),
                FailoverSecurityRealmTest::realmHttpMechanisms,
                FailoverSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        if (FAILOVER_REALM_USERS.exists()) {
            FAILOVER_REALM_USERS.delete();
        }
        if (FAILOVER_REALM_ROLES.exists()) {
            FAILOVER_REALM_ROLES.delete();
        }

        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try (PrintStream out = new PrintStream(new FileOutputStream(FAILOVER_REALM_USERS))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), identity.password()));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating users properties file for properties security realm failed: " + ex.getMessage());
        }

        try (PrintStream out = new PrintStream(new FileOutputStream(FAILOVER_REALM_ROLES))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), "admin"));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating roles properties file for properties security realm failed: " + ex.getMessage());
        }

        try {
            managementClient.execute(String.format("/subsystem=datasources/data-source=%s:add(driver-name=h2, "
                    + "jndi-name=\"java:jboss/datasources/%s\", "
                    + "connection-url=\"jdbc:h2:mem:test;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;MODE=REGULAR\", "
                    + "user-name=sa, password=sa, enabled=true)",
                    DELEGATE_REALM_NAME, DELEGATE_REALM_NAME)).assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "principal-query=[{sql=\"invalid SQL\", data-source=%s, "
                    + "clear-password-mapper={password-index=1}, attribute-mapping=[{index=2,to=\"groups\"}]}])",
                    DELEGATE_REALM_TYPE, DELEGATE_REALM_NAME, DELEGATE_REALM_NAME)).assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "users-properties={path=%s, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=%s, relative-to=jboss.server.config.dir})",
                    FAILOVER_REALM_TYPE, FAILOVER_REALM_NAME, FAILOVER_REALM_USERS_PATH, FAILOVER_REALM_ROLES_PATH))
                    .assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add(delegate-realm=%s, failover-realm=%s)",
                    REALM_TYPE, REALM_NAME, DELEGATE_REALM_NAME, FAILOVER_REALM_NAME))
                    .assertSuccess();
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
                    DELEGATE_REALM_TYPE, DELEGATE_REALM_NAME)).assertSuccess();
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    FAILOVER_REALM_TYPE, FAILOVER_REALM_NAME)).assertSuccess();
                managementClient.execute(String.format("/subsystem=datasources/data-source=%s:remove", DELEGATE_REALM_NAME))
                        .assertSuccess();
                realmRegistered = false;
            }
        } catch (CliException e) {
            throw new IOException("Unable to remove security realm configuration.", e);
        }
    }

    static Set<SaslAuthenticationMechanism> realmSaslMechanisms() {
        return EnumSet.of(SaslAuthenticationMechanism.PLAIN,
                SaslAuthenticationMechanism.DIGEST_MD5,
                SaslAuthenticationMechanism.DIGEST_SHA,
                SaslAuthenticationMechanism.DIGEST_SHA_256,
                SaslAuthenticationMechanism.DIGEST_SHA_384,
                SaslAuthenticationMechanism.DIGEST_SHA_512);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.DIGEST_MD5,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
