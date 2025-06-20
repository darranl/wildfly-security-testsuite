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
import java.util.HashSet;
import java.util.Set;

import org.hsqldb.jdbc.JDBCDataSource;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.security.auth.realm.jdbc.JdbcSecurityRealm;
import org.wildfly.security.auth.realm.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a database.
 */
public class JdbcSecurityRealmTest extends AbstractAuthenticationSuite {

    private static JDBCDataSource dataSource;

    @BeforeSuite
    public static void setup() throws Exception {
        registerProvider();
        //setMode("JDBC");

        Set<String> supportedMechanims = new HashSet<>();
        Collections.addAll(supportedMechanims, "PLAIN");

        createDataSource();

        //createTestServer(JdbcSecurityRealmTest::createSecurityRealm,
        //        Collections.unmodifiableSet(supportedMechanims));
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
}
