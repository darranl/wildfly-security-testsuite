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
import org.wildfly.extras.creaper.core.ManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineOptions;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFamily;
import org.wildfly.security.tests.common.authauthz.TestFilter;
import org.wildfly.security.tests.common.authauthz.TransportType;
import org.wildfly.security.tests.common.authauthz.http.HttpTestClient;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;

/**
 * Runner for brute force attack protection HTTP mechanism testing.
 */
public class BruteForceAuthnProtectionHttpSuiteRunner extends AbstractHttpSuiteRunner {

    HttpTestClient testClient = HttpTestClient.builder()
                .withToUri(AbstractHttpSuiteRunner::toURI)
                .build();

    static String realmName() {
        return AbstractAuthenticationSuite.getSecurityRealmRegistrar().getRealmName();
    }

    @TestFactory
    Stream<DynamicTest> dynamicHttpTests() {
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<HttpAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms();

        TestFilter testFilter = TestFilter.getInstance();
        String realmType = AbstractAuthenticationSuite.realmType();

        supportedMechnisms.forEach(mechanism -> {
            if (testFilter.shouldRunTest(mechanism, TestFamily.BRUTE_FORCE, "BruteForceAttemptsExceeded")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceAttemptsExceeded(%s)", realmType, mechanism),
                                () -> testHttpBruteForceAttemptsExceeded(mechanism)));
            }
        });

        // tests per realm
        HttpAuthenticationMechanism mechanism = supportedMechnisms.iterator().next();
        if (testFilter.shouldRunTest(TransportType.HTTP, TestFamily.BRUTE_FORCE, "BruteForceDisabled")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceDisabled(%s)", realmType, mechanism),
                                () -> testHttpBruteForceDisabled(mechanism)));
        }
        if (testFilter.shouldRunTest(TransportType.HTTP, TestFamily.BRUTE_FORCE, "BruteForceLockoutInterval")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceLockoutInterval(%s)", realmType, mechanism),
                                () -> testHttpBruteForceLockoutInterval(mechanism)));
        }
        if (testFilter.shouldRunTest(TransportType.HTTP, TestFamily.BRUTE_FORCE, "BruteForceSessionTimeout")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceSessionTimeout(%s)", realmType, mechanism),
                                () -> testHttpBruteForceSessionTimeout(mechanism)));
        }

        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    public void testHttpBruteForceAttemptsExceeded(final HttpAuthenticationMechanism mechanism) throws Exception {
        testClient.testHttpBadPassword(mechanism, "user1", "passwordX");
        testClient.testHttpBadPassword(mechanism, "user1", "passwordX");
        testClient.testHttpBadPassword(mechanism, "user1", "password1");

        testClient.testHttpSuccess(mechanism, "user2", "password2");
        testClient.testHttpBadPassword(mechanism, "user2", "passwordX");
        testClient.testHttpBadPassword(mechanism, "user2", "passwordX");
        testClient.testHttpBadPassword(mechanism, "user2", "password2");
    }

    public void testHttpBruteForceLockoutInterval(final HttpAuthenticationMechanism mechanism) throws Exception {
        testClient.testHttpBadPassword(mechanism, "user3", "passwordX");
        testClient.testHttpBadPassword(mechanism, "user3", "passwordX");
        Thread.sleep(61000);
        testClient.testHttpSuccess(mechanism, "user3", "password3");
    }

    public void testHttpBruteForceSessionTimeout(final HttpAuthenticationMechanism mechanism) throws Exception {
        testClient.testHttpBadPassword(mechanism, "user4", "passwordX");
        Thread.sleep(61000);
        testClient.testHttpBadPassword(mechanism, "user4", "passwordX");
        testClient.testHttpSuccess(mechanism, "user4", "password4");
    }

    public void testHttpBruteForceDisabled(final HttpAuthenticationMechanism mechanism) throws Exception {
        try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
            client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:add(value=false)", realmName())).assertSuccess();
            new Administration(client).reload();
        }
        try {
            testClient.testHttpBadPassword(mechanism, "user5", "passwordX");
            testClient.testHttpBadPassword(mechanism, "user5", "passwordX");
            testClient.testHttpBadPassword(mechanism, "user5", "password5");
        } finally {
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:remove", realmName())).assertSuccess();
                new Administration(client).reload();
            }
        }
    }
}
