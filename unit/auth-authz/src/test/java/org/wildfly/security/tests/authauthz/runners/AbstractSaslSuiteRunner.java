/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static java.util.stream.Collectors.toSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.initialised;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedAction;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServerFactory;

import org.jboss.remoting3.Connection;
import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.spi.NetworkServerProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.util.ServiceLoaderSaslServerFactory;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.xnio.IoFuture;
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

    private Endpoint endpoint;
    private Closeable streamServer;

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
        streamServer = networkServerProvider.createServer(new InetSocketAddress("localhost", 30123),
                optionMap, saslAuthenticationFactory, serverContext);
    }

    /**
     * Create the {@code SecurityDomain} used for testing.
     *
     * This method is not static so the runners can optionally override it.
     *
     * @return the {@code SecurityDomain} used for testing.
     */
    protected SecurityDomain createSecurityDomain() {
        return AbstractAuthenticationSuite.createSecurityDomain();
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

    protected void performSaslTest(final String mechanism, final String userName,
                                 final String password, final boolean expectSuccess) throws IOException {

        AuthenticationContext authContext = AuthenticationContext.empty()
                .with(MatchRule.ALL, AuthenticationConfiguration.empty()
                        .useName(userName)
                        .usePassword(password)
                        .setSaslMechanismSelector(SaslMechanismSelector.fromString(mechanism))
                );

        Endpoint endpoint = getEndpoint();

        IoFuture<Connection> futureConnection = authContext.run(
                (PrivilegedAction<IoFuture<Connection>>) () ->
                        endpoint.connect(toUri("remote://localhost:30123"),
                                optionMap)
        );

        IoFuture.Status status = futureConnection.await(5000, TimeUnit.MILLISECONDS);

        if (expectSuccess) {
            assertEquals(IoFuture.Status.DONE, status, "Expected IoFuture to be DONE");
            try (Connection connection = futureConnection.get()) {
                assertNotNull(connection, "Expected a connection to have been opened");
            }
        } else {
            assertEquals(IoFuture.Status.FAILED, status, "Expected IoFuture to be FAILED");
            Exception e = futureConnection.getException();
            assertEquals(SaslException.class, e.getClass(), "Expected SaslException");
            assertTrue(e.getMessage().contains("rejected authentication"), "Expected authentication to be rejected.");
        }
    }

    static URI toUri(final String uri) {
        try {
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
