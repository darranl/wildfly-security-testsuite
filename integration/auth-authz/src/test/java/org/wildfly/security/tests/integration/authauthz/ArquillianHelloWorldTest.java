/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.container.annotation.ArquillianTest;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.Test;

/**
 * A simple Arquillian based hello world test.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@ArquillianTest
@RunAsClient
public class ArquillianHelloWorldTest {

    @ArquillianResource
    private URI uri;

    @Deployment()
    public static WebArchive deployment() {
        return ShrinkWrap.create(WebArchive.class, "hello-world.war")
                .addClass(HelloWorldServlet.class);
    }

    @Test
    public void testHello() throws Exception {
        System.out.println(uri.toString());
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet get = new HttpGet(uri.toString() + "/hello");
            String result = client.execute(get, response -> {
                return EntityUtils.toString(response.getEntity());
            });

            assertEquals("Hello World", result, "Expected servlet response.");
        }
    }
}
