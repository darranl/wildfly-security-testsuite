/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.util.Map;
import java.util.Set;

/**
 * A context implementation to obtain information about the current suite.
 *
 * Different suites may have some subtle differences that dynamic tests need to
 * compensate for.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class TestContext {

    private final Map<Transport, Set<String>> transportMechMap;

    TestContext(final Map<Transport, Set<String>> transportMechMap) {
        this.transportMechMap = transportMechMap;
    }

    Set<Transport> enabledTransports() {
        return transportMechMap.keySet();
    }

    Set<String> mechanismsForTransport(final Transport transport) {
        return transportMechMap.get(transport);
    }

    enum Transport {
        HTTP, SASL;
    }

}
