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
    private static final String TEST_NAME_FILTER = "TestFilter.TestName";

    private final Predicate<TransportType> transportTypePredicate;
    private final Predicate<String> testNamePredicate;
    private final Predicate<HttpAuthenticationMechanism> httpMechanismPredicate;
    private final Predicate<SaslAuthenticationMechanism> saslMechanismPredicate;

    private static final TestFilter INSTANCE = new TestFilter();

    private TestFilter() {
        String transportTypeFilter = System.getProperty(TRANSPORT_TYPE_FILTER, null);
        if (transportTypeFilter != null) {
            String[] transports = transportTypeFilter.split(",");
            final Set<TransportType> enabledTransports = new HashSet<>(transports.length);
            for (String currentTransport : transports) {
                enabledTransports.add(TransportType.valueOf(currentTransport));
            }

            transportTypePredicate = enabledTransports::contains;
        } else {
            transportTypePredicate = t -> true;
        }

        String testNameFilter = System.getProperty(TEST_NAME_FILTER, null);
        if (testNameFilter != null) {
            String[] testNames = testNameFilter.split(",");
            final Set<String> enabledTestNames = new HashSet<>(testNames.length);
            Collections.addAll(enabledTestNames, testNames);

            testNamePredicate = enabledTestNames::contains;
        } else {
            testNamePredicate = n -> true;
        }

        String httpMechanismFilter = System.getProperty(HTTP_MECHANISM_FILTER, null);
        if (httpMechanismFilter != null) {
            String[] mechanisms = httpMechanismFilter.split(",");
            final Set<HttpAuthenticationMechanism> enabledMechanisms = new HashSet<>(mechanisms.length);
            for (String currentMechanism : mechanisms) {
                enabledMechanisms.add(HttpAuthenticationMechanism.valueOf(currentMechanism));
            }

            httpMechanismPredicate = enabledMechanisms::contains;
        } else {
            httpMechanismPredicate = m -> true;
        }

        String saslMechanismFilter = System.getProperty(SASL_MECHANISM_FILTER, null);
        if (saslMechanismFilter != null) {
            String[] mechanisms = saslMechanismFilter.split(",");
            final Set<SaslAuthenticationMechanism> enabledMechanisms = new HashSet<>(mechanisms.length);
            for (String currentMechanism : mechanisms) {
                enabledMechanisms.add(SaslAuthenticationMechanism.valueOf(currentMechanism));
            }

            saslMechanismPredicate = enabledMechanisms::contains;
        } else {
            saslMechanismPredicate = m -> true;
        }
    }

    public static TestFilter getInstance() {
        return INSTANCE;
    }

    private boolean shouldRunTest(TransportType transport, String testName) {
        return transportTypePredicate.test(transport) && testNamePredicate.test(testName);
    }

    public boolean shouldRunTest(HttpAuthenticationMechanism mechanism, String testName) {
        return shouldRunTest(TransportType.HTTP, testName) && httpMechanismPredicate.test(mechanism);
    }

    public boolean shouldRunTest(SaslAuthenticationMechanism mechanism, String testName) {
        return shouldRunTest(TransportType.SASL, testName) && saslMechanismPredicate.test(mechanism);
    }
}
