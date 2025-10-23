/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import org.jboss.shrinkwrap.api.asset.StringAsset;

/**
 * Common code shared to work with deployments.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DeploymentUtility {

    static StringAsset createJBossWebXml(String securityDomain) {
        return new StringAsset(String.format("<jboss-web><security-domain>%s</security-domain></jboss-web>", securityDomain));
    }

}
