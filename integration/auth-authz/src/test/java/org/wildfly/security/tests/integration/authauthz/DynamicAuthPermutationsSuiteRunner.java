/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.net.URI;
import java.util.stream.Stream;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.container.annotation.ArquillianTest;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.integration.authauthz.TestContext.Transport;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@ArquillianTest
@RunAsClient
public class DynamicAuthPermutationsSuiteRunner {

    @ArquillianResource
    private URI uri;

    @Deployment()
    public static WebArchive deployment() {
        return ShrinkWrap.create(WebArchive.class, "hello-world.war")
                .addClass(HelloWorldServlet.class);
    }

    @TestFactory
    Stream<DynamicTest> dynamicTests() {
        return Stream.of(Transport.values())
                .map(t ->
                    dynamicTest("My Test",
                            () -> System.out.printf("Running DynamicTest for mode '%s' for transport '%s' and URI = '%s'\n",
                                    AbstractAuthenticationSuite.getMode(), t.name(), uri.toString())));
    }

}
