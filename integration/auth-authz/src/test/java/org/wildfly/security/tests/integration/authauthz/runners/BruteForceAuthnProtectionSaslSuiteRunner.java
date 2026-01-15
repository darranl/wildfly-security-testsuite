/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.jboss.as.arquillian.api.ServerSetup;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.extras.creaper.core.ManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineOptions;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFamily;
import org.wildfly.security.tests.common.authauthz.TestFilter;
import org.wildfly.security.tests.common.authauthz.TransportType;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;

@ServerSetup(BruteForceAuthnProtectionSaslSuiteRunner.ConfigurationServerSetupTask.class)
public class BruteForceAuthnProtectionSaslSuiteRunner extends AbstractSaslSuiteRunner {

    static String realmName() {
        return AbstractAuthenticationSuite.getSecurityRealmRegistrar().getRealmName();
    }

     @TestFactory
    Stream<DynamicTest> dynamicSaslTests() {
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<SaslAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms();

        TestFilter testFilter = TestFilter.getInstance();

        String realmType = AbstractAuthenticationSuite.realmType();

        // tests per mechanism
        supportedMechnisms.forEach(s -> {
            if (testFilter.shouldRunTest(s, TestFamily.BRUTE_FORCE, "BruteForceAttemptsExceeded")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceAttemptsExceeded(%s)", realmType, s),
                                () -> testSaslBruteForceAttemptsExceeded(s)));
            }
        });

        // tests per realm
        SaslAuthenticationMechanism mechanism = supportedMechnisms.iterator().next();
        if (testFilter.shouldRunTest(TransportType.SASL, TestFamily.BRUTE_FORCE, "BruteForceDisabled")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceDisabled(%s)", realmType, mechanism),
                                () -> testSaslBruteForceDisabled(mechanism)));
        }
        if (testFilter.shouldRunTest(TransportType.SASL, TestFamily.BRUTE_FORCE, "testSaslBruteForceLockoutInterval")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceLockoutInterval(%s)", realmType, mechanism),
                                () -> testSaslBruteForceLockoutInterval(mechanism)));
        }
        if (testFilter.shouldRunTest(TransportType.SASL, TestFamily.BRUTE_FORCE, "testSaslBruteForceSessionTimeout")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceSessionTimeout(%s)", realmType, mechanism),
                                () -> testSaslBruteForceSessionTimeout(mechanism)));
        }

        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    public void testSaslBruteForceAttemptsExceeded(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceAttemptsExceeded(%s)\n", mechanism);

        performSaslTest(mechanism.getMechanismName(), "user1", "passwordX", false);
        performSaslTest(mechanism.getMechanismName(), "user1", "passwordX", false);
        performSaslTest(mechanism.getMechanismName(), "user1", "password1", false);

        // TODO investigate why this does not work
        //testSaslEjbConnection(mechanism.getMechanismName(), "user2", "password2", true);
        performSaslTest(mechanism.getMechanismName(), "user2", "passwordX", false);
        performSaslTest(mechanism.getMechanismName(), "user2", "passwordX", false);
        performSaslTest(mechanism.getMechanismName(), "user2", "password2", false);
    }

    // TODO is it ok to test this just for one mech per realm? Also, it would be great if we could set short lockout interval for tests (1 minute now).
    public void testSaslBruteForceLockoutInterval(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceLockoutInterval(%s)\n", mechanism);

        performSaslTest(mechanism.getMechanismName(), "user3", "passwordX", false);
        performSaslTest(mechanism.getMechanismName(), "user3", "passwordX", false);
        Thread.sleep(61000);
        performSaslTest(mechanism.getMechanismName(), "user3", "password3", true);
    }

    // TODO is it ok to test this just for one mech per realm? Also, it would be great if we could set short session timout for tests (1 minute now).
    public void testSaslBruteForceSessionTimeout(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceSessionTimeout(%s)\n", mechanism);

        performSaslTest(mechanism.getMechanismName(), "user4", "passwordX", false);
        Thread.sleep(121000);
        performSaslTest(mechanism.getMechanismName(), "user4", "passwordX", false);
        performSaslTest(mechanism.getMechanismName(), "user4", "password4", true);
    }

    public void testSaslBruteForceDisabled(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceDisabled(%s)\n", mechanism);
        try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
            client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:add(value=false)", realmName())).assertSuccess();
            new Administration(client).reload();
        }

        try {
            performSaslTest(mechanism.getMechanismName(), "user5", "passwordX", false);
            performSaslTest(mechanism.getMechanismName(), "user5", "passwordX", false);
            performSaslTest(mechanism.getMechanismName(), "user5", "password5", true);
        } finally {
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:remove", realmName())).assertSuccess();
                new Administration(client).reload();
            }
        }
    }

    public static class ConfigurationServerSetupTask extends AbstractSaslSuiteRunner.ConfigurationServerSetupTask {

        @Override
        protected Map<String, String> getRequiredSystemProperties() {
            Map<String, String> properties = new HashMap<>();
            properties.put(String.format("wildfly.elytron.realm.%s.brute-force.max-failed-attempts", realmName()), "2");
            properties.put(String.format("wildfly.elytron.realm.%s.brute-force.lockout-interval", realmName()), "1");
            properties.put(String.format("wildfly.elytron.realm.%s.brute-force.session-timeout", realmName()), "2");
            return properties;
        }

    }
}
