/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite.nextIdentity;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFamily;
import org.wildfly.security.tests.common.authauthz.TestFilter;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite.IdentityDefinition;

public class StandardSaslSuiteRunner extends AbstractSaslSuiteRunner {

    @TestFactory
    Stream<DynamicTest> dynamicSaslTests() {
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

    public void testSaslSuccess(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslSuccess(%s)\n", mechanism);

        IdentityDefinition identityOne = nextIdentity();
        performSaslTest(mechanism.getMechanismName(), identityOne.username(), identityOne.password(), true);
    }

    public void testSaslBadUsername(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBadUsername(%s)\n", mechanism);

        performSaslTest(mechanism.getMechanismName(), "Bob", "password1", false);
    }

    public void testSaslBadPassword(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBadPassword(%s)\n", mechanism);

        IdentityDefinition identityOne = nextIdentity();
        performSaslTest(mechanism.getMechanismName(), identityOne.username(), "passwordX", false);
    }
}
