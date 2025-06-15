/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import io.undertow.Undertow;

/**
 * Base class for the Http Suite Runners.
 *
 * This class is responsible for setting up the HTTP server under test.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
abstract class AbstractHttpSuiteRunner {

    private Undertow undertowServer;

    /**
     * Set up the server process to be used by the tests.
     */
    @BeforeEach
    public void startServer() {
        System.out.println("AbstractHttpSuiteRunner->startServer()");
        Undertow.Builder undertowBuilder = Undertow.builder();
        undertowBuilder.addHttpListener(8080, "localhost");
        undertowServer = undertowBuilder.build();
        undertowServer.start();
    }

    /**
     * Stop the server process previously started for testing.
     */
    @AfterEach
    public void stopServer() {
        System.out.println("AbstractHttpSuiteRunner->stopServer()");
        if (undertowServer != null) {
            undertowServer.stop();
            undertowServer = null;
        }
    }
}
