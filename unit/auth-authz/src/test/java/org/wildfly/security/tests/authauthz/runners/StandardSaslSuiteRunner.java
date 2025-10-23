/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.security.sasl.SaslException;

import org.jboss.remoting3.Connection;
import org.jboss.remoting3.Endpoint;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFilter;
import org.xnio.IoFuture;

/**
 * A runner for standard SASL authentication against the configured {@code SecurityRealm}.
 *
 * By "Standard" this runner handles standard success / failure scenarios based on good
 * and bad usernames / passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class StandardSaslSuiteRunner extends AbstractSaslSuiteRunner {

    @TestFactory
    Stream<DynamicTest> dynamicSaslTests() {
        // By the time this is called startServer() will have been called in our parent
        // so we don't need the static method calls, instead we get get the policy info from
        // our parent.
        System.out.println("StandardSaslSuiteRunner->dynamicSaslTests");
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<SaslAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms();

        TestFilter testFilter = TestFilter.getInstance();

        String realmType = AbstractAuthenticationSuite.realmType();
        supportedMechnisms.forEach(s -> {
            if (testFilter.shouldRunTest(s, "Success")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslSuccess(%s)", realmType, s), () -> testSaslSuccess(s)));
            }

            if (testFilter.shouldRunTest(s, "BadUsername")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBadUsername(%s)", realmType, s),
                                () -> testSaslBadUsername(s)));
            }

            if (testFilter.shouldRunTest(s, "BadPassword")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBadPassword(%s)", realmType, s),
                                () -> testSaslBadPassword(s)));
            }
        });

        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    public void testSaslSuccess(final SaslAuthenticationMechanism mechanism) throws IOException {
        System.out.printf("testSaslSuccess(%s)\n", mechanism);

        performSaslTest(mechanism.getMechanismName(), "user1", "password1", true);
    }

    public void testSaslBadUsername(final SaslAuthenticationMechanism mechanism) throws IOException {
        System.out.printf("testSaslBadUsername(%s)\n", mechanism);

        performSaslTest(mechanism.getMechanismName(), "Bob", "password1", false);
    }

    public void testSaslBadPassword(final SaslAuthenticationMechanism mechanism) throws IOException {
        System.out.printf("testSaslBadPassword(%s)\n", mechanism);

        performSaslTest(mechanism.getMechanismName(), "user1", "passwordX", false);
    }

    private void performSaslTest(final String mechanism, final String userName,
                                 final String password, final boolean expectSuccess) throws IOException {

        AuthenticationContext authContext = AuthenticationContext.empty()
                .with(MatchRule.ALL, AuthenticationConfiguration.empty()
                        .useName(userName)
                        .usePassword(password)
                        .setSaslMechanismSelector(SaslMechanismSelector.fromString(mechanism))
                );

        Endpoint endpoint = getEndpoint();

        IoFuture<Connection> futureConnection = authContext.run(
                (PrivilegedAction<IoFuture<Connection>>) () ->
                        endpoint.connect(toUri("remote://localhost:30123"),
                                optionMap)
        );

        IoFuture.Status status = futureConnection.await(5000, TimeUnit.MILLISECONDS);

        if (expectSuccess) {
            assertEquals(IoFuture.Status.DONE, status, "Expected IoFuture to be DONE");
            try (Connection connection = futureConnection.get()) {
                assertNotNull(connection, "Expected a connection to have been opened");
            }
        } else {
            assertEquals(IoFuture.Status.FAILED, status, "Expected IoFuture to be FAILED");
            Exception e = futureConnection.getException();
            assertEquals(SaslException.class, e.getClass(), "Expected SaslException");
            assertTrue(e.getMessage().contains("rejected authentication"), "Expected authentication to be rejected.");
        }
    }

    static URI toUri(final String uri) {
        try {
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
