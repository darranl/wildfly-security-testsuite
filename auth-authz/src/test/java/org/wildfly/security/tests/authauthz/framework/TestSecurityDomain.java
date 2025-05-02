/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.framework;

import java.io.Closeable;

import org.wildfly.security.auth.server.SecurityDomain;

/**
 * Test utility to represent a {@code SecurityDomain} that has been
 * configured for testing.
 *
 * This utility implements {@code Closeable} for resource clean up.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface TestSecurityDomain extends Closeable {

    SecurityDomain get();

}
