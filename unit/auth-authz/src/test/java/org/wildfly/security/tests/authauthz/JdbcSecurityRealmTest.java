/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.hsqldb.jdbc.JDBCDataSource;
import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.jdbc.JdbcSecurityRealm;
import org.wildfly.security.auth.realm.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a database.
 */
public class JdbcSecurityRealmTest extends AbstractAuthenticationSuite {

    private static JDBCDataSource dataSource;

    @BeforeSuite
    public static void setup() throws Exception {
        // Create and local resources needed for the SecurityRealm
        createDataSource();
        // Begin any server processes needed by the realm, either in-vm or test containers.
        //  N/A
        // Register a factory for instantiating a security realm instance.
        //  - In integration testing this last step may be register a utility to define the realm in mgmt.
        register("Map", JdbcSecurityRealmTest::createSecurityRealm,
                JdbcSecurityRealmTest::realmHttpMechanisms,
                JdbcSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() {
        // Stop any server processes created for the realm either in-vm or test containers.
        // Clean up any filesystem resources for this realm.

        // This impl was in memory so garbage collection is sufficient.
        register(null, null, null, null);
    }

    static SecurityRealm createSecurityRealm() {
        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
                .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
                .setHashColumn(1)
                .build();
        JdbcSecurityRealm realm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password FROM jdbc_realm_users WHERE username = ?")
                .withMapper(passwordKeyMapper)
                .from(dataSource)
                .build();
        return realm;
    }

    private static void createDataSource() throws SQLException {
        dataSource = new JDBCDataSource();
        dataSource.setDatabase("mem:jdbc-security-realm-test");
        dataSource.setUser("sa");
        createUsersTable();
        insertUsers();
    }

    private static void createUsersTable() throws SQLException {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement()) {

            statement.executeUpdate("DROP TABLE IF EXISTS jdbc_realm_users");
            statement.executeUpdate("CREATE TABLE jdbc_realm_users (username VARCHAR(50), password VARCHAR(50), PRIMARY KEY(username))");
        }
    }

    private static void insertUsers() throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("INSERT INTO jdbc_realm_users (username, password) VALUES (?, ?)")) {

            for (IdentityDefinition identity : obtainTestIdentities().toList()) {
                statement.setString(1, identity.username());
                statement.setString(2, identity.password());
                statement.executeUpdate();
            }
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
        return Collections.emptySet();
//        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
//                HttpAuthenticationMechanism.DIGEST_MD5,
//                HttpAuthenticationMechanism.FORM,
//                HttpAuthenticationMechanism.PROGRAMATIC);
    }
}
