/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;

/**
 * A runner for standard HTTP authentication against the configured {@code SecurityRealm}.
 *
 * By "Standard" this runner handles standard success / failure scenarios based on good
 * and bad usernames / passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class StandardHttpSuiteRunner extends AbstractHttpSuiteRunner {

    @TestFactory
    Stream<DynamicTest> dynamicHttpTests() {
        // By the time this is called startServer() will have been called in our parent
        // so we don't need the static method calls, instead we get get the policy info from
        // our parent.
        System.out.println("StandardHttpSuiteRunner->dynamicHttpTests");
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<HttpAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms();

        String realmType = AbstractAuthenticationSuite.realmType();
        supportedMechnisms.forEach(s -> {
            dynamicTests.add(
                    dynamicTest(String.format("[%s] testHttpSuccess(%s)", realmType, s), () -> testHttpSuccess(s)));
            dynamicTests.add(
                    dynamicTest(String.format("[%s] testHttpBadUsername(%s)", realmType, s), () -> testHttpBadUsername(s)));
            dynamicTests.add(
                    dynamicTest(String.format("[%s] testHttpBadPassword(%s)", realmType, s), () -> testHttpBadPassword(s)));
        });

        if (dynamicTests.isEmpty()) {
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    public void testHttpSuccess(final HttpAuthenticationMechanism mechanism) {
        System.out.printf("testHttpSuccess(%s)\n", mechanism);
    }

    public void testHttpBadUsername(final HttpAuthenticationMechanism mechanism) {
        System.out.printf("testHttpBadUsername(%s)\n", mechanism);
    }

    public void testHttpBadPassword(final HttpAuthenticationMechanism mechanism) {
        System.out.printf("testHttpBadPassword(%s)\n", mechanism);
    }
}
