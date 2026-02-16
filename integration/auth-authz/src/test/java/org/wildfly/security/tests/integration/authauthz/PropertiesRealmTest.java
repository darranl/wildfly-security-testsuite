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
 * Variant of the {@code AbstractAuthenticationSuite} to test the properties based security realm.
 */
public class PropertiesRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-properties-realm";
    private static final String REALM_TYPE = "properties-realm";

    private static final File REALM_USERS = SERVER_CONFIG_DIR.resolve("test-realm-users.properties").toFile();
    private static final File REALM_ROLES = SERVER_CONFIG_DIR.resolve("test-realm-roles.properties").toFile();

    private volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                                            PropertiesRealmTest::registerSecurityRealm, PropertiesRealmTest::removeSecurityRealm),
                PropertiesRealmTest::realmHttpMechanisms,
                PropertiesRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        if (REALM_USERS.exists()) {
            REALM_USERS.delete();
        }
        if (REALM_ROLES.exists()) {
            REALM_ROLES.delete();
        }

        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try (PrintStream out = new PrintStream(new FileOutputStream(REALM_USERS))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), identity.password()));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating users properties file for properties security realm failed: " + ex.getMessage());
        }

        try (PrintStream out = new PrintStream(new FileOutputStream(REALM_ROLES))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), "admin"));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating roles properties file for properties security realm failed: " + ex.getMessage());
        }

        try {
            managementClient.execute("/subsystem=elytron/properties-realm=test-properties-realm:add("
                    + "users-properties={path=test-realm-users.properties, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=test-realm-roles.properties, relative-to=jboss.server.config.dir})")
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
                SaslAuthenticationMechanism.DIGEST_SHA_512,
                SaslAuthenticationMechanism.SCRAM_SHA_1,
                SaslAuthenticationMechanism.SCRAM_SHA_256,
                SaslAuthenticationMechanism.SCRAM_SHA_384,
                SaslAuthenticationMechanism.SCRAM_SHA_512);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.DIGEST_MD5,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
