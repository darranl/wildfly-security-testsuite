/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFamily;
import org.wildfly.security.tests.common.authauthz.TestFilter;

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
            if (testFilter.shouldRunTest(s, TestFamily.STANDARD, "Success")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslSuccess(%s)", realmType, s), () -> testSaslSuccess(s)));
            }

            if (testFilter.shouldRunTest(s, TestFamily.STANDARD, "BadUsername")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBadUsername(%s)", realmType, s),
                                () -> testSaslBadUsername(s)));
            }

            if (testFilter.shouldRunTest(s, TestFamily.STANDARD, "BadPassword")) {
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

}
