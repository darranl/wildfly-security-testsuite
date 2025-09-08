/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.common.authauthz.deployment;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@SuppressWarnings("serial")
@WebServlet("/hello")
public class HelloWorldServlet extends HttpServlet {

    public static final String PRINCIPAL_HEADER = "HelloWorldServlet.HttpServletRequest.Principal";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Principal p = req.getUserPrincipal();
        resp.addHeader(PRINCIPAL_HEADER, p != null ? p.getName() : "null");

        try (PrintWriter writer = resp.getWriter()) {
            writer.print("Hello World");
        }
    }

}
