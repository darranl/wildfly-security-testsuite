/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.common.authauthz;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Utility to make it possible to filter which dynamic tests run.
 *
 * This filter takes into account, transport, mechanism, and test name.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class TestFilter {

    private static final String TRANSPORT_TYPE_FILTER = "TestFilter.TransportType";
    private static final String HTTP_MECHANISM_FILTER = "TestFilter.HttpAuthenticationMechanism";
    private static final String SASL_MECHANISM_FILTER = "TestFilter.SaslAuthenticationMechanism";
    private static final String TEST_FAMILY_FILTER = "TestFilter.TestFamily";
    private static final String TEST_NAME_FILTER = "TestFilter.TestName";

    private final Predicate<TransportType> transportTypePredicate;
    private final Predicate<TestFamily> testFamilyPredicate;
    private final Predicate<String> testNamePredicate;
    private final Predicate<HttpAuthenticationMechanism> httpMechanismPredicate;
    private final Predicate<SaslAuthenticationMechanism> saslMechanismPredicate;

    private static final TestFilter INSTANCE = new TestFilter();

    private TestFilter() {
        transportTypePredicate = createPredicate(TransportType.class, TRANSPORT_TYPE_FILTER);
        testFamilyPredicate = createPredicate(TestFamily.class, TEST_FAMILY_FILTER);
        testNamePredicate = createPredicate(TEST_NAME_FILTER);
        httpMechanismPredicate = createPredicate(HttpAuthenticationMechanism.class, HTTP_MECHANISM_FILTER);
        saslMechanismPredicate = createPredicate(SaslAuthenticationMechanism.class, SASL_MECHANISM_FILTER);
    }

    private static Predicate<String> createPredicate(final String systemProperty) {
        String filter = System.getProperty(systemProperty, null);
        if (filter != null) {
            String[] testValues = filter.split(",");
            final Set<String> enabledValues = new HashSet<>(testValues.length);
            Collections.addAll(enabledValues, testValues);

            return enabledValues::contains;
        } else {
            return n -> true;
        }
    }

    private static <T extends Enum<T>> Predicate<T> createPredicate(Class<T> enumClass, String systemProperty) {
        String filter = System.getProperty(systemProperty, null);
        if (filter != null) {
            String[] values = filter.split(",");
            final Set<T> enabledValues = new HashSet<>(values.length);
            for (String currentValue : values) {
                enabledValues.add(T.valueOf(enumClass, currentValue));
            }

            return enabledValues::contains;
        } else {
            return m -> true;
        }
    }

    public static TestFilter getInstance() {
        return INSTANCE;
    }

    public boolean shouldRunTest(TransportType transport, TestFamily family, String testName) {
        return transportTypePredicate.test(transport) && testFamilyPredicate.test(family) && testNamePredicate.test(testName);
    }

    public boolean shouldRunTest(HttpAuthenticationMechanism mechanism, TestFamily family, String testName) {
        return shouldRunTest(TransportType.HTTP, family, testName) && httpMechanismPredicate.test(mechanism);
    }

    public boolean shouldRunTest(SaslAuthenticationMechanism mechanism, TestFamily family, String testName) {
        return shouldRunTest(TransportType.SASL, family, testName) && saslMechanismPredicate.test(mechanism);
    }
}
