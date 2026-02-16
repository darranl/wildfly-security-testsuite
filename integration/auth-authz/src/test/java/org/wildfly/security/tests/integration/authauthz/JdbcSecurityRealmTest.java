/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import org.h2.tools.Server;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.extras.creaper.core.online.CliException;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * Variant of the {@code AbstractAuthenticationSuite} to test the JDBC security realm.
 */
public class JdbcSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-jdbc-realm";
    private static final String REALM_TYPE = "jdbc-realm";

    private static final String DB_TCP_PORT = "8094";
    private static final String DB_DRIVER_CLASS_NAME = "org.h2.Driver";
    private static final String DB_URL = String.format("jdbc:h2:tcp://localhost:%s/mem:jdbcrealmtest;DB_CLOSE_DELAY=-1", DB_TCP_PORT);
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "sa";

    private volatile static boolean realmRegistered = false;
    private static Server dbServer;

    @BeforeSuite
    public static void beginRealm() {
        startDatabase();
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                                         JdbcSecurityRealmTest::registerSecurityRealm, JdbcSecurityRealmTest::removeSecurityRealm),
            JdbcSecurityRealmTest::realmHttpMechanisms,
            JdbcSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        register(null, null, null);
        stopDatabase();
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try {
            managementClient.execute(String.format("/subsystem=datasources/data-source=%s:add(driver-name=h2, "
                    + "jndi-name=\"java:jboss/datasources/%s\", connection-url=\"%s\", user-name=%s, password=%s, enabled=true)",
                    REALM_NAME, REALM_NAME, DB_URL, DB_USER, DB_PASSWORD)).assertSuccess();
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add("
                    + "principal-query=[{sql=\"SELECT password, roles FROM jdbc_realm_users WHERE username = ?\", data-source=%s, "
                    + "clear-password-mapper={password-index=1}, attribute-mapping=[{index=2,to=\"groups\"}]}])",
                    REALM_TYPE, REALM_NAME, REALM_NAME)).assertSuccess();
            realmRegistered = true;
        } catch (CliException e) {
            throw new IOException("Unable to register security realm configuration.", e);
        }

        try (Connection connection = getDBConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP TABLE IF EXISTS jdbc_realm_users");
                statement.execute("CREATE TABLE jdbc_realm_users (username VARCHAR(50), password VARCHAR(50), roles VARCHAR(50), PRIMARY KEY(username))");
            }

            try (PreparedStatement statement = connection.prepareStatement("INSERT INTO jdbc_realm_users (username, password, roles) VALUES (?, ?, ?)")) {
                for (IdentityDefinition identity : obtainTestIdentities().collect(Collectors.toList())) {
                    statement.setString(1, identity.username());
                    statement.setString(2, identity.password());
                    statement.setString(3, "admin");
                    statement.executeUpdate();
                }
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable create table with users in H2 DB", ex);
        }
    }

    static void removeSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        if (realmRegistered) {
            try {
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove", REALM_TYPE, REALM_NAME)).assertSuccess();
                managementClient.execute(String.format("/subsystem=datasources/data-source=%s:remove", REALM_NAME)).assertSuccess();
                new Administration(managementClient).reloadIfRequired();
                realmRegistered = false;
            } catch (CliException | InterruptedException | TimeoutException e) {
                throw new IOException("Unable to remove security realm configuration.", e);
            }

            try (Connection connection = getDBConnection(); Statement statement = connection.createStatement()) {
                statement.execute("DROP TABLE IF EXISTS jdbc_realm_users");
            } catch (SQLException ex) {
                throw new IllegalStateException("Unable to drop table with users in H2 DB", ex);
            }
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

    private static void startDatabase() {
        try {
            dbServer = Server.createTcpServer("-tcpPort", DB_TCP_PORT, "-tcpAllowOthers", "-ifNotExists").start();
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to start TCP server for H2 DB", ex);
        }
    }

    private static void stopDatabase() {
        if (dbServer != null && dbServer.isRunning(true)) {
            dbServer.stop();
        }
    }

    private static Connection getDBConnection() {
        try {
            Class.forName(DB_DRIVER_CLASS_NAME);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Unable to get class for H2 DB driver " + DB_DRIVER_CLASS_NAME, e);
        }
        try {
            return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        } catch (SQLException e) {
            throw new IllegalStateException("Unable to get H2 DB connection", e);
        }
    }

}
