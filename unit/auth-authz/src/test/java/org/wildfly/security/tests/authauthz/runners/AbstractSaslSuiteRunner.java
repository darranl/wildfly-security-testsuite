/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static java.util.stream.Collectors.toSet;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.createSecurityDomain;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.initialised;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.security.sasl.SaslServerFactory;

import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.spi.NetworkServerProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.sasl.util.ServiceLoaderSaslServerFactory;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.xnio.OptionMap;
import org.xnio.Options;

/**
 * Base class for the SASL Suite Runners.
 *
 * This class is responsible for setting up the Remoting server under test.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
abstract class AbstractSaslSuiteRunner {

    static final OptionMap optionMap = OptionMap.create(Options.SSL_ENABLED, Boolean.FALSE);

    private int port = 30123;

    private Endpoint endpoint;
    private Closeable streamServer;

    String getUri() {
        return String.format("remote://localhost:%d", port);
    }

    @BeforeEach
    public void startServer() throws Exception {
        System.out.println("AbstractSaslSuiteRunner->startServer()");
        if (!initialised()) {
            System.out.println("AbstractSaslSuiteRunner - NOT INITIALISED");
            return;
        }

        endpoint = Endpoint.builder()
                .setEndpointName(
                        String.format("%sEndpoint", AbstractSaslSuiteRunner.class.getName()))
                .build();
        NetworkServerProvider networkServerProvider = endpoint.getConnectionProviderInterface("remote", NetworkServerProvider.class);

        SaslServerFactory saslServerFactory = new ServiceLoaderSaslServerFactory(AbstractAuthenticationSuite.class.getClassLoader());

        Set<String> supportedMechanismNames = supportedSaslAuthenticationMechanisms().stream()
                .map(SaslAuthenticationMechanism::getMechanismName)
                .collect(toSet());
        SaslAuthenticationFactory saslAuthenticationFactory =  SaslAuthenticationFactory.builder()
                .setSecurityDomain(createSecurityDomain())
                .setFactory(saslServerFactory)
                .setMechanismConfigurationSelector(mechanismInformation -> supportedMechanismNames.contains(mechanismInformation.getMechanismName()) ? MechanismConfiguration.EMPTY : null)
                .build();

        final SSLContext serverContext = SSLContext.getDefault();
        streamServer = networkServerProvider.createServer(new InetSocketAddress("localhost", ++port),
                optionMap, saslAuthenticationFactory, serverContext);
    }

    protected Endpoint getEndpoint() {
        return endpoint;
    }

    @AfterEach
    public void stopServer() throws IOException {
        // TODO Make Safe for close();
        if (streamServer != null) {
            streamServer.close();
            streamServer = null;
        }
        if (endpoint != null) {
            endpoint.close();
            streamServer = null;
        }
    }
}
