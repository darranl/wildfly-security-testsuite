/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite.getMode;
import static org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite.getTestContext;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.container.annotation.ArquillianTest;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.common.authauthz.HelloWorldServlet;
import org.wildfly.security.tests.common.authauthz.TestContext;
import org.wildfly.security.tests.common.authauthz.TestContext.Transport;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@ArquillianTest
@RunAsClient
public class DynamicAuthPermutationsSuiteRunner {

    @ArquillianResource
    private URI uri;

    @Deployment()
    public static WebArchive deployment() {
        return ShrinkWrap.create(WebArchive.class, "hello-world.war")
                .addClass(HelloWorldServlet.class);
    }

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
                            () -> System.out.printf("Running DynamicTest for mode '%s' for transport '%s' and URI = '%s'\n",
                                    AbstractAuthenticationSuite.getMode(), t.name(), uri.toString())));
    }

    public void testSaslSuccess(final String mechanism) throws IOException {
        System.out.printf("testSaslSuccess(%s)\n", mechanism);
    }

    public void testSaslBadUsername(final String mechanism) throws IOException {
        System.out.printf("testSaslBadUsername(%s)\n", mechanism);
    }

    public void testSaslBadPassword(final String mechanism) throws IOException {
        System.out.printf("testSaslBadPassword(%s)\n", mechanism);
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
