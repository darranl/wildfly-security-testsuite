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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.Set;
import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.extras.creaper.core.ManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineOptions;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * Variant of the {@code AbstractAuthenticationSuite} to test the properties based security realm.
 */
public class PropertiesRealmTest extends AbstractAuthenticationSuite {

    private static final Path SERVER_CONFIG_DIR = Paths.get(System.getProperty("jboss.home")).toAbsolutePath()
            .resolve("standalone").resolve("configuration");
    private static final File REALM_USERS = SERVER_CONFIG_DIR.resolve("test-realm-users.properties").toFile();
    private static final File REALM_ROLES = SERVER_CONFIG_DIR.resolve("test-realm-roles.properties").toFile();

    @BeforeSuite
    public static void beginRealm() {
        register("properties-realm", PropertiesRealmTest::createSecurityRealm,
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

        register(null, null, null, null);
    }

    static String createSecurityRealm() {
        try (PrintStream out = new PrintStream(new FileOutputStream(REALM_USERS))) {
            obtainTestIdentities().forEach(identity -> {
                out.println(String.format("%s=%s", identity.username(), identity.password()));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating users properties file for properties security realm failed: " + ex.getMessage());
        }

        try (PrintStream out = new PrintStream(new FileOutputStream(REALM_ROLES))) {
            obtainTestIdentities().findFirst().ifPresent(identity -> {
                out.println(String.format("%s=%s", identity.username(), "admin"));
            });
        } catch (FileNotFoundException ex) {
            throw new IllegalStateException("Creating roles properties file for properties security realm failed: " + ex.getMessage());
        }

        try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
            client.execute("/subsystem=elytron/properties-realm=test-properties-realm:add("
                    + "users-properties={path=test-realm-users.properties, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=test-realm-roles.properties, relative-to=jboss.server.config.dir})")
                    .assertSuccess();
        } catch (Exception ex) {
            throw new IllegalStateException("Creating properties security realm failed: " + ex.getMessage());
        }
        return "test-properties-realm";
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
                HttpAuthenticationMechanism.PROGRAMATIC);
    }
}
