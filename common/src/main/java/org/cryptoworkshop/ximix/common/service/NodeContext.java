/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.common.service;

import java.io.File;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;

public interface NodeContext

{
    /**
     * Return the name of the node this context represents.
     *
     * @return our node's name.
     */
    String getName();

    Map<String, ServicesConnection> getPeerMap();

    CapabilityMessage[] getCapabilities();

    SubjectPublicKeyInfo getPublicKey(String keyID);

    boolean hasPrivateKey(String keyID);

    PublicKeyOperator getPublicKeyOperator(String keyID);

    PrivateKeyOperator getPrivateKeyOperator(String keyID);

    boolean shutdown(int time, TimeUnit timeUnit)
        throws InterruptedException;

    boolean isStopCalled();

    void execute(Runnable task);

    void schedule(Runnable task, long time, TimeUnit timeUnit);

    Executor getDecoupler(Decoupler task);

    ScheduledExecutorService getScheduledExecutor();

    ThresholdKeyPairGenerator getKeyPairGenerator(Algorithm algorithm);

    String getBoardHost(String boardName);

    File getHomeDirectory();

    Future<Map<Service,Map<String,Object>>> getServiceStatistics();

    Map<String,String> getDescription();

    ListeningSocketInfo getListeningSocketInfo();

}
