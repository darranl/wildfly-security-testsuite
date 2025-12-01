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
 * Variant of the {@code AbstractAuthenticationSuite} to test the aggregate security realm
 * based on properties security realms.
 */
public class AggregateSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-aggregate-realm";
    private static final String REALM_TYPE = "aggregate-realm";
    private static final String AUTHN_REALM_NAME = "test-authn-properties-realm";
    private static final String AUTHN_REALM_TYPE = "properties-realm";
    private static final String AUTHZ_REALM_NAME = "test-authz-properties-realm";
    private static final String AUTHZ_REALM_TYPE = "properties-realm";

    private static final String AUTHN_REALM_USERS_PATH = "test-authn-realm-users.properties";
    private static final File AUTHN_REALM_USERS = SERVER_CONFIG_DIR.resolve(AUTHN_REALM_USERS_PATH).toFile();
    private static final String AUTHZ_REALM_ROLES_PATH = "test-authz-realm-roles.properties";
    private static final File AUTHZ_REALM_ROLES = SERVER_CONFIG_DIR.resolve(AUTHZ_REALM_ROLES_PATH).toFile();

    private volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                                            AggregateSecurityRealmTest::registerSecurityRealm, AggregateSecurityRealmTest::removeSecurityRealm),
                AggregateSecurityRealmTest::realmHttpMechanisms,
                AggregateSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        if (AUTHN_REALM_USERS.exists()) {
            AUTHN_REALM_USERS.delete();
        }
        if (AUTHZ_REALM_ROLES.exists()) {
            AUTHZ_REALM_ROLES.delete();
        }

        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try (PrintStream out = new PrintStream(new FileOutputStream(AUTHN_REALM_USERS))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), identity.password()));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating users properties file for properties security realm failed: " + ex.getMessage());
        }

        try (PrintStream out = new PrintStream(new FileOutputStream(AUTHZ_REALM_ROLES))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), "admin"));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating roles properties file for properties security realm failed: " + ex.getMessage());
        }

        try {
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "users-properties={path=%s, plain-text=true, relative-to=jboss.server.config.dir})",
                    AUTHN_REALM_TYPE, AUTHN_REALM_NAME, AUTHN_REALM_USERS_PATH))
                    .assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "users-properties={path=%s, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=%s, relative-to=jboss.server.config.dir})",
                    AUTHZ_REALM_TYPE, AUTHZ_REALM_NAME, AUTHN_REALM_USERS_PATH, AUTHZ_REALM_ROLES_PATH))
                    .assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "authentication-realm=%s,authorization-realms=[%s])",
                    REALM_TYPE, REALM_NAME, AUTHN_REALM_NAME, AUTHZ_REALM_NAME))
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
                    AUTHN_REALM_TYPE, AUTHN_REALM_NAME)).assertSuccess();
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    AUTHZ_REALM_TYPE, AUTHZ_REALM_NAME)).assertSuccess();
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
