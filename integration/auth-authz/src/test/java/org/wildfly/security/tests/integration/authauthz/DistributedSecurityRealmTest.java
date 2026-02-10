/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.EnumSet;
import java.util.List;
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

    private static final String REALM_ONE = "properties-realm-one";
    private static final String REALM_ONE_USERS = "test-properties-realm-one-users.properties";
    private static final String REALM_ONE_ROLES = "test-properties-realm-one-roles.properties";

    private static final String REALM_TWO = "properties-realm-two";
    private static final String REALM_TWO_USERS = "test-properties-realm-two-users.properties";
    private static final String REALM_TWO_ROLES = "test-properties-realm-two-roles.properties";


    private static final String REALM_THREE = "properties-realm-three";
    private static final String REALM_THREE_USERS = "test-properties-realm-three-users.properties";
    private static final String REALM_THREE_ROLES = "test-properties-realm-three-roles.properties";

    private static final String PROPERTIES_REALM_TYPE = "properties-realm";


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
        delete(REALM_ONE_USERS);
        delete(REALM_ONE_ROLES);
        delete(REALM_TWO_USERS);
        delete(REALM_TWO_ROLES);
        delete(REALM_THREE_USERS);
        delete(REALM_THREE_ROLES);
        register(null, null, null);
    }

    private static void delete(String fileName)  {
        File file = SERVER_CONFIG_DIR.resolve(fileName).toFile();
        if (file.exists()) {
            file.delete();
        }
    }

    private static int index = 0;

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        PrintStream[] usersFiles = new PrintStream[3];
        PrintStream[] rolesFiles = new PrintStream[3];

        try {
            usersFiles[0] = new PrintStream(new FileOutputStream(SERVER_CONFIG_DIR.resolve(REALM_ONE_USERS).toFile()));
            usersFiles[1] = new PrintStream(new FileOutputStream(SERVER_CONFIG_DIR.resolve(REALM_TWO_USERS).toFile()));
            usersFiles[2] = new PrintStream(new FileOutputStream(SERVER_CONFIG_DIR.resolve(REALM_THREE_USERS).toFile()));
            rolesFiles[0] = new PrintStream(new FileOutputStream(SERVER_CONFIG_DIR.resolve(REALM_ONE_ROLES).toFile()));
            rolesFiles[1] = new PrintStream(new FileOutputStream(SERVER_CONFIG_DIR.resolve(REALM_TWO_ROLES).toFile()));
            rolesFiles[2] = new PrintStream(new FileOutputStream(SERVER_CONFIG_DIR.resolve(REALM_THREE_ROLES).toFile()));

            index = 0;
            obtainTestIdentities().forEach(identity -> {
                usersFiles[index].println(String.format("%s=%s", identity.username(), identity.password()));
                rolesFiles[index].println(String.format("%s=%s", identity.username(), "admin"));
                index = (index + 1) % 3;
            });

        } finally {
            for (int i = 0 ; i < usersFiles.length ; i++) {
                if (usersFiles[i] != null) usersFiles[i].close();
                usersFiles[i] = null;
                if (rolesFiles[i] != null) rolesFiles[i].close();
                rolesFiles[i] = null;
            }
        }

        try {
            // setup underlying realms differently so that we test that their configuration is not taken into account
            for (String realmName : List.of(REALM_TWO, REALM_THREE)) {
                managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.max-failed-attempts:add(value=20)", realmName)).assertSuccess();
                managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.lockout-interval:add(value=10)", realmName)).assertSuccess();
                managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.session-timeout:add(value=20)", realmName)).assertSuccess();
            }
            managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:add(value=false)", REALM_ONE)).assertSuccess();

            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "users-properties={path=%s, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=%s, relative-to=jboss.server.config.dir})",
                    PROPERTIES_REALM_TYPE, REALM_ONE, REALM_ONE_USERS, REALM_ONE_ROLES))
                    .assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "users-properties={path=%s, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=%s, relative-to=jboss.server.config.dir})",
                    PROPERTIES_REALM_TYPE, REALM_TWO, REALM_TWO_USERS, REALM_TWO_ROLES))
                    .assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "users-properties={path=%s, plain-text=true, relative-to=jboss.server.config.dir}, "
                    + "groups-properties={path=%s, relative-to=jboss.server.config.dir})",
                    PROPERTIES_REALM_TYPE, REALM_THREE, REALM_THREE_USERS, REALM_THREE_ROLES))
                    .assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add(realms=[%s,%s,%s])",
                    REALM_TYPE, REALM_NAME, REALM_ONE, REALM_TWO, REALM_THREE)).assertSuccess();
            realmRegistered = true;
        } catch (CliException e) {
            throw new IOException("Unable to register security realm configuration.", e);
        }

    }

    static void removeSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try {
            if (realmRegistered) {
                managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:remove", REALM_ONE)).assertSuccess();
                for (String realmName : List.of(REALM_TWO, REALM_THREE)) {
                    managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.max-failed-attempts:remove", realmName)).assertSuccess();
                    managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.lockout-interval:remove", realmName)).assertSuccess();
                    managementClient.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.session-timeout:remove", realmName)).assertSuccess();
                }
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    REALM_TYPE, REALM_NAME)).assertSuccess();
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    PROPERTIES_REALM_TYPE, REALM_ONE)).assertSuccess();
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    PROPERTIES_REALM_TYPE, REALM_TWO)).assertSuccess();
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    PROPERTIES_REALM_TYPE, REALM_THREE)).assertSuccess();
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
