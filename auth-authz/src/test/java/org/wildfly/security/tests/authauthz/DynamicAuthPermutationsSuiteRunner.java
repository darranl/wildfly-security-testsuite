/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.getEndpoint;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.getMode;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.getTestContext;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.toUri;

import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
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
import org.wildfly.security.tests.authauthz.TestContext.Transport;
import org.xnio.IoFuture;

/**
 * A runner for a realm specific suite that dynamically defines the tests to run.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DynamicAuthPermutationsSuiteRunner {

    @TestFactory
    Stream<DynamicTest> dynamicSaslTests() {
        List<DynamicTest> dynamicTests = new ArrayList<>();

        TestContext testContext = getTestContext();
        if (testContext != null && testContext.enabledTransports().contains(Transport.SASL)) {
            final String mode = getMode();
            testContext.mechanismsForTransport(Transport.SASL).forEach(
                    s -> {
                        dynamicTests.add(dynamicTest(String.format("[%s] testSaslSuccess(%s)", mode, s),
                                () -> testSaslSuccess(s)));
                        dynamicTests.add(dynamicTest(String.format("[%s] testSaslBadUsername(%s)", mode, s),
                                () -> testSaslBadUsername(s)));
                        dynamicTests.add(dynamicTest(String.format("[%s] testSaslBadPassword(%s)", mode, s),
                                () -> testSaslBadPassword(s)));
                        dynamicTests.add(dynamicTest(String.format("[%s] testSaslBruteForce(%s)", mode, s),
                                () -> testSaslBruteForce(s)));
                    }
            );
        }
        return dynamicTests.stream();
    }

    @TestFactory
    Stream<DynamicTest> dynamicHttpTests() {
        List<DynamicTest> dynamicTests = new ArrayList<>();

        TestContext testContext = getTestContext();
        if (testContext != null && testContext.enabledTransports().contains(Transport.HTTP)) {
            final String mode = getMode();
            testContext.mechanismsForTransport(Transport.HTTP).forEach(
                    s -> {
                        dynamicTests.add(dynamicTest(String.format("[%s] testHttpSuccess(%s)", mode, s),
                                () -> testHttpSuccess(s)));
                        dynamicTests.add(dynamicTest(String.format("[%s] testHttpBadUsername(%s)", mode, s),
                                () -> testHttpBadUsername(s)));
                        dynamicTests.add(dynamicTest(String.format("[%s] testHttpBadPassword(%s)", mode, s),
                                () -> testHttpBadPassword(s)));
                        dynamicTests.add(dynamicTest(String.format("[%s] testHttpBruteForce(%s)", mode, s),
                                () -> testHttpBruteForce(s)));
                    }
            );
        }

        return dynamicTests.stream();
    }

    @TestFactory
    Stream<DynamicTest> dynamicTests() {
        return Stream.of(Transport.values())
                .map(t ->
                    dynamicTest("My Test",
                            () -> System.out.printf("Running DynamicTest for mode '%s' for transport '%s'\n",
                                    AbstractAuthenticationSuite.getMode(), t.name())));
    }

    public void testSaslSuccess(final String mechanism) throws IOException {
        System.out.printf("testSaslSuccess(%s)\n", mechanism);

        performSaslTest(mechanism, "user1", "password1", true);
    }

    public void testSaslBadUsername(final String mechanism) throws IOException {
        System.out.printf("testSaslBadUsername(%s)\n", mechanism);

        performSaslTest(mechanism, "Bob", "password1", false);
    }

    public void testSaslBadPassword(final String mechanism) throws IOException {
        System.out.printf("testSaslBadPassword(%s)\n", mechanism);

        performSaslTest(mechanism, "user1", "passwordX", false);
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
                                AbstractAuthenticationSuite.optionMap)
        );

        IoFuture.Status status = futureConnection.await(500, TimeUnit.MILLISECONDS);

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

    public void testSaslBruteForce(final String mechanism) {
        System.out.printf("testSaslBruteForce(%s)\n", mechanism);
    }

    public void testHttpSuccess(final String mechanism) {
        System.out.printf("testHttpSuccess(%s)\n", mechanism);
    }

    public void testHttpBadUsername(final String mechanism) {
        System.out.printf("testHttpBadUsername(%s)\n", mechanism);
    }

    public void testHttpBadPassword(final String mechanism) {
        System.out.printf("testHttpBadPassword(%s)\n", mechanism);
    }

    public void testHttpBruteForce(final String mechanism) {
        System.out.printf("testHttpBruteForce(%s)\n", mechanism);
    }

}
