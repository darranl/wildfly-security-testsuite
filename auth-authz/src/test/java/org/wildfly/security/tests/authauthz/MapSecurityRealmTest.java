/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import org.junit.platform.suite.api.BeforeSuite;

/**
 * A {@code Suite} instance for testing against a {@code SecurityRealm} backed by a {@code Map}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class MapSecurityRealmTest extends AbstractAuthenticationSuite {

    @BeforeSuite
    public static void setup() {
        setMode("MAP");
    }

}
