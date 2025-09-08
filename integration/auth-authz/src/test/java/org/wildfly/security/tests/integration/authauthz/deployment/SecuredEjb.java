package org.wildfly.security.tests.integration.authauthz.deployment;

import jakarta.annotation.Resource;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ejb.Remote;
import jakarta.ejb.SessionContext;
import jakarta.ejb.Stateless;
import java.security.Principal;

@Stateless
@RolesAllowed("admin")
@Remote(SecuredEjbRemote.class)
public class SecuredEjb implements SecuredEjbRemote {

    @Resource
    private SessionContext ctx;

    @Override
    public String getPrincipalName() {
        Principal principal = ctx.getCallerPrincipal();
        return principal.toString();
    }
}
