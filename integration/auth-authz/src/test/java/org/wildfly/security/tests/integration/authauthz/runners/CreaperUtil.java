/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import java.io.IOException;

import org.wildfly.extras.creaper.core.ManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineOptions;

/**
 * Simple utility to interact with some Creaper capabilities.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CreaperUtil {

    public static OnlineManagementClient onlineManagementClient() throws IOException {
        return ManagementClient.online(OnlineOptions.standalone().localDefault().build());
    }

}
