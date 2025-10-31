/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.IOException;
import java.util.function.Supplier;

import org.wildfly.common.function.ExceptionConsumer;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;

/**
 * A registrar responsible for handing the registration and de-registration of
 * security realms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface SecurityRealmRegistrar {

    /**
     * Returns the type of the security realm.
     *
     * @return the type of the security realm.
     */
    public String getRealmType();

    /**
     * Returns the name the security realm will be / is registered to on the
     * application server under test.
     *
     * @return the name the security realm is registered under.
     */
    public String getRealmName();


    /**
     * Register the security realm with the application server.
     *
     * This registration may also register dependent resources and invoke additional
     * management operations to completely initialise the realm.
     *
     * @param managementClient A connected {@code OnlineManagementClient} to interact
     * with the target server.
     * @throws IOException If any error occurs performing the registration.
     */
    public void register(OnlineManagementClient managementClient) throws IOException;

    /**
     * Unregister the previously registered security realm and associated resources.
     *
     * This method should unregister the previous successful registrations in the call
     * to {@code #register(OnlineManagementClient)}, if that method has not been called
     * or if that method did not successfully register anything this method should silently
     * return.
     *
     * @param managementClient A connected {@code OnlineManagementClient} to interact
     * with the target server.
     * @throws IOException If any error occurs performing the unRegistration.
     */
    public void unRegister(OnlineManagementClient managementClient) throws IOException;

    public static SecurityRealmRegistrar create(Supplier<String> realmTypeSupplier,
                                                Supplier<String> realmNameSupplier,
                                                ExceptionConsumer<OnlineManagementClient, IOException> registerConsumer,
                                                ExceptionConsumer<OnlineManagementClient, IOException> unRegisterConsumer) {
        return new SecurityRealmRegistrar() {

            @Override
            public String getRealmType() {
                return realmTypeSupplier.get();
            }

            @Override
            public String getRealmName() {
                return realmNameSupplier.get();
            }

            @Override
            public void register(OnlineManagementClient managementClient) throws IOException {
                registerConsumer.accept(managementClient);
            }

            @Override
            public void unRegister(OnlineManagementClient managementClient) throws IOException {
                unRegisterConsumer.accept(managementClient);
            }

        };
    }
}
