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
     * This is the name of the security realm that the {@code SecurityDomain}
     * will reference.
     *
     * @return the name the security realm is registered under.
     */
    public String getPrimaryRealmName();


    /**
     * The primary security realm may be delegating to one or more delegate
     * realms.
     *
     * These are the realms that additional test configuration may be applied
     * such as brute force protection.
     *
     * The name of the delegate realm will match the primary realm when no
     * additional delegates exist.
     *
     * @return An array of delegate realm names.
     */
    public String[] getDelegateRealmNames();


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
        return create(realmTypeSupplier, realmNameSupplier, () -> new String[] { realmNameSupplier.get() }, registerConsumer, unRegisterConsumer);
    }

    public static SecurityRealmRegistrar create(Supplier<String> realmTypeSupplier,
                                                Supplier<String> primaryRealmNameSupplier,
                                                Supplier<String[]> delegateRealmNameSupplier,
                                                ExceptionConsumer<OnlineManagementClient, IOException> registerConsumer,
                                                ExceptionConsumer<OnlineManagementClient, IOException> unRegisterConsumer) {
        return new SecurityRealmRegistrar() {

            @Override
            public String getRealmType() {
                return realmTypeSupplier.get();
            }

            @Override
            public String getPrimaryRealmName() {
                return primaryRealmNameSupplier.get();
            }

            @Override
            public String[] getDelegateRealmNames() {
                return delegateRealmNameSupplier.get();
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
