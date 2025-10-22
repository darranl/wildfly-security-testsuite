/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFamily;
import org.wildfly.security.tests.common.authauthz.TestFilter;
import org.wildfly.security.tests.common.authauthz.http.HttpTestClient;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;

/**
 * Runner for standard HTTP mechanism testing.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class StandardHttpSuiteRunner extends AbstractHttpSuiteRunner {

    @TestFactory
    Stream<DynamicTest> dynamicHttpTests() {
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<HttpAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms();

        TestFilter testFilter = TestFilter.getInstance();
        String realmType = AbstractAuthenticationSuite.realmType();
        HttpTestClient testClient = HttpTestClient.builder()
                                        .withToUri(AbstractHttpSuiteRunner::toURI)
                                        .build();

        supportedMechnisms.forEach(s -> {
            if (testFilter.shouldRunTest(s, TestFamily.STANDARD, "Success")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpSuccess(%s)", realmType, s), () -> testClient.testHttpSuccess(s)));
            }

            if (testFilter.shouldRunTest(s, TestFamily.STANDARD, "BadUsername")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBadUsername(%s)", realmType, s),
                                () -> testClient.testHttpBadUsername(s)));
            }

            if (testFilter.shouldRunTest(s, TestFamily.STANDARD, "BadPassword")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBadPassword(%s)", realmType, s),
                                () -> testClient.testHttpBadPassword(s)));
            }
        });

        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

}
