/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.getMode;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.getTestContext;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.common.authauthz.TestContext;
import org.wildfly.security.tests.common.authauthz.TestContext.Transport;

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
                    }
            );
        }

        return dynamicTests.stream();
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
}
