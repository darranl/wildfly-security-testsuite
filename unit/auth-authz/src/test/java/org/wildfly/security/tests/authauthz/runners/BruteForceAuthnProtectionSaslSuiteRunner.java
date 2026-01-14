/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.auth.realm.BruteForceRealmWrapper;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFamily;
import org.wildfly.security.tests.common.authauthz.TestFilter;

/**
 * A runner for testing brute force protection over SASL against the configured {@code SecurityRealm}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BruteForceAuthnProtectionSaslSuiteRunner extends AbstractSaslSuiteRunner {

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
            if (testFilter.shouldRunTest(s, TestFamily.BRUTE_FORCE, "SuccessfulAuth")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSuccessfulAuth(%s)", realmType, s), () -> testSuccessfulAuth(s)));
            }

            if (testFilter.shouldRunTest(s, TestFamily.BRUTE_FORCE, "DisabledIdentity")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testDisabledIdentity(%s)", realmType, s), () -> testDisabledIdentity(s)));
            }

            if (testFilter.shouldRunTest(s, TestFamily.BRUTE_FORCE, "SuccessAfterBad")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSuccessAfterBad(%s)", realmType, s), () -> testSuccessAfterBad(s)));
            }

            if (testFilter.shouldRunTest(s, TestFamily.BRUTE_FORCE, "NonExistant")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testNonExistant(%s)", realmType, s), () -> testNonExistant(s, realmType.equals("JAAS"))));
            }

            if (testFilter.shouldRunTest(s, TestFamily.BRUTE_FORCE, "SingleSessionTimeout")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSingleSessionTimeout(%s)", realmType, s), () -> testSingleSessionTimeout(s)));
            }
        });


        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    private ScheduledExecutorUtility scheduledExecutorUtility = new ScheduledExecutorUtility();

    @Override
    protected SecurityDomain createSecurityDomain() {
        return AbstractAuthenticationSuite.createSecurityDomain(s -> {
            return BruteForceRealmWrapper.create()
                .wrapping(s)
                .withExecutor(scheduledExecutorUtility.createScheduledExecutorService())
                .setMaxFailedAttempts(5)
                .setLockoutInterval(5)
                .setFailureSessionTimeout(2)
                .wrap(SecurityRealm.class);
        });
    }

    /**
     * Perform 10 successful authentications and verify no lockout occurs.
     */
    public void testSuccessfulAuth(SaslAuthenticationMechanism m) throws Exception {
        for (int i = 0; i < 10; i++) {
            performSaslTest(m.getMechanismName(), "user1", "password1", true);
            assertEquals(0, scheduledExecutorUtility.sessionCount(), "No session should exist.");
        }
    }

    /**
     * Make a single call to verify the test identity works.
     * Make 5 bad calls to trigger a lockout (5 is the configured maximum)
     * Make one "good" call and verify it is locked out.
     * Trigger the session timeout.
     * Make one good call and verify it succeeds again.
     */
    public void testDisabledIdentity(SaslAuthenticationMechanism m) throws Exception {
        performSaslTest(m.getMechanismName(), "user1", "password1", true);
        assertEquals(0, scheduledExecutorUtility.sessionCount(), "No session should exist.");

        for (int i = 0; i < 5; i++) {
            performSaslTest(m.getMechanismName(), "user1", "badpassword", false); // This call uses the good username but bad password.
            assertEquals(1, scheduledExecutorUtility.sessionCount(), "One session should exist.");
        }
        // The username and password in the next call are correct, but it should still behave
        // as though the password is bad.
        performSaslTest(m.getMechanismName(), "user1", "password1", false);
        scheduledExecutorUtility.simulateTimeoutAll();
        performSaslTest(m.getMechanismName(), "user1", "password1", true);
        assertEquals(0, scheduledExecutorUtility.sessionCount(), "No session should exist.");
    }

    /**
     * Call once successfully to verify it is working.
     * Make 4 bad calls, we should have a session but nothing should be locked out.
     * Make one good call, this should succeed and clear the session.
     * Make another 4 bad calls, again not enough to trigger lockout.
     * Finish with one more good call.
     *
     * This test has 8 bad calls in total but the good call in the middle prevents the
     * identity from being locked out.
     */
    public void testSuccessAfterBad(SaslAuthenticationMechanism m) throws Exception {
        performSaslTest(m.getMechanismName(), "user1", "password1", true);
        assertEquals(0, scheduledExecutorUtility.sessionCount(), "No session should exist.");

        for (int j = 0; j < 2; j++) {
            for (int i = 0; i < 4; i++) {
                performSaslTest(m.getMechanismName(), "user1", "badpassword", false); // This call uses the good username but bad password.
                assertEquals(1, scheduledExecutorUtility.sessionCount(), "One session should exist.");
            }
            // This successful call resets the protection
            performSaslTest(m.getMechanismName(), "user1", "password1", true);
            assertEquals(0, scheduledExecutorUtility.sessionCount(), "No session should exist.");
        }
    }

    /**
     * Make 5 calls as a user that does not exist.
     *   No session should be created.
     */
    public void testNonExistant(SaslAuthenticationMechanism m, boolean expectSession) throws Exception {
        for (int i = 0; i < 5; i++) {
            performSaslTest(m.getMechanismName(), "baduser", "badpassword", false);
            assertEquals(expectSession ? 1 : 0, scheduledExecutorUtility.sessionCount(),
                    expectSession ? "One session expected" : "No session should exist.");
        }
        scheduledExecutorUtility.simulateTimeoutAll();
    }

    /**
     * Verify identity 1 originally works.
     * Make 5 bad calls as one identity to trigger lockout.
     * Verify identity 1 is locked out.
     * Grab the scheduled future for identity 1.
     *
     * Verify identity 2 originally works.
     * Make 5 bad calls as identity 2 to trigger lockout.
     * verify identity 2 is locked out.
     * verify identity 1 is still locked out.
     *
     * Trigger timeout for identity 1.
     * Verify identity 1 now works.
     * Verify identity 2 still locked out.
     *
     * Trigger all timeouts.
     * Verify both identities work.
     */
    public void testSingleSessionTimeout(SaslAuthenticationMechanism m) throws Exception {
        performSaslTest(m.getMechanismName(), "user1", "password1", true);
        assertEquals(0, scheduledExecutorUtility.sessionCount(), "No session should exist.");

        for (int i = 0; i < 5; i++) {
            performSaslTest(m.getMechanismName(), "user1", "badpassword", false);
            assertEquals(1, scheduledExecutorUtility.sessionCount(), "One session should exist.");
        }
        // The username and password in the next call are correct, but it should still behave
        // as though the password is bad.
        performSaslTest(m.getMechanismName(), "user1", "password1", false);

        ScheduledFuture sf = scheduledExecutorUtility.getScheduledFutures().iterator().next();

        performSaslTest(m.getMechanismName(), "user2", "password2", true);
        assertEquals(1, scheduledExecutorUtility.sessionCount(), "Just the original session should exist.");

        for (int i = 0; i < 5; i++) {
            performSaslTest(m.getMechanismName(), "user2", "badpassword", false);
            assertEquals(2, scheduledExecutorUtility.sessionCount(), "Two sessions should exist.");
        }
        // The username and password in the next call are correct, but it should still behave
        // as though the password is bad.
        performSaslTest(m.getMechanismName(), "user2", "password2", false);

        scheduledExecutorUtility.simulateTimeout(sf);
        // user1 should now be clear, user2 should still be blocked
        performSaslTest(m.getMechanismName(), "user1", "password1", true);
        performSaslTest(m.getMechanismName(), "user2", "password2", false);

        scheduledExecutorUtility.simulateTimeoutAll();
        performSaslTest(m.getMechanismName(), "user1", "password1", true);
        performSaslTest(m.getMechanismName(), "user2", "password2", true);
        assertEquals(0, scheduledExecutorUtility.sessionCount(), "No session should exist.");
    }

}
