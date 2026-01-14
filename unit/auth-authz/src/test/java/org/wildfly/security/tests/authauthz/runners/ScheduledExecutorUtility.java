/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;


/**
 * A simple utility used where we need a {@code ScheduledExecutorService}.
 *
 * This utility is not intended to be a complete mock implementation and just
 * covers the capabilities we need to interact with.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ScheduledExecutorUtility {

    private final Map<ScheduledFuture, Runnable> scheduledRunnables;

    ScheduledExecutorUtility() {
        scheduledRunnables = new HashMap<>();
    }

    Set<ScheduledFuture> getScheduledFutures() {
        return scheduledRunnables.keySet();
    }

    void simulateTimeout(ScheduledFuture future) {
        Runnable r = scheduledRunnables.remove(future);
        if (r != null) {
            r.run();
        }
    }

    int sessionCount() {
        return scheduledRunnables.size();
    }

    void simulateTimeoutAll() {
        scheduledRunnables.forEach((k, v) -> v.run());
        scheduledRunnables.clear();
    }

    ScheduledExecutorService createScheduledExecutorService() {
        return (ScheduledExecutorService) Proxy.newProxyInstance(ScheduledExecutorUtility.class.getClassLoader(),
            new Class[] { ScheduledExecutorService.class }, new ScheduledExecutorInvocationHandler());
    }

    static Method getTargetMethod() {
        try {
            return ScheduledExecutorService.class.getMethod("schedule", Runnable.class, long.class, TimeUnit.class);
        } catch (NoSuchMethodException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private class ScheduledExecutorInvocationHandler implements InvocationHandler {

        final Method TARGET_METHOD = getTargetMethod();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (TARGET_METHOD.equals(method)) {
                if (args[0] instanceof Runnable) {
                    TestScheduledFuture future = new TestScheduledFuture((p) -> scheduledRunnables.remove(p) != null);
                    scheduledRunnables.put(future, (Runnable)args[0]);

                    return future;
                }

                throw new IllegalArgumentException("Expected Runnable");
            } else {
                return null;
            }
        }
    }

    private static class TestScheduledFuture implements ScheduledFuture {

        private final Function<Object, Boolean> cancel;

        private boolean isCancelled = false;

        public TestScheduledFuture(Function<Object, Boolean> cancel) {
            this.cancel = cancel;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            // Not relevant to test.
            return 0;
        }


        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            return cancel.apply(this);
        }

        @Override
        public Object get() throws InterruptedException, ExecutionException {
            // Not relevant to test.
            return null;
        }

        @Override
        public Object get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            // Not relevant to test.
            return null;
        }

        @Override
        public boolean isCancelled() {
            return isCancelled;
        }

        @Override
        public boolean isDone() {
            // Not relevant to test.
            return false;
        }

        @Override
        public int compareTo(Object o) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'compareTo'");
        }

    }
}
