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
package org.cryptoworkshop.ximix.node.service;

import java.io.File;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Interface that a node's context conforms to.
 */
public interface NodeContext
{
    /**
     * Return the name of the node this context represents.
     *
     * @return our node's name.
     */
    String getName();

    Map<String, ServicesConnection> getPeerMap();

    /**
     * Return the combined capabilities of all services in this node.
     *
     * @return the node's capabilities.
     */
    CapabilityMessage[] getCapabilities();

    /**
     * Return the network public key identified by keyID.
     *
     * @param keyID the key ID of interest.
     * @return a SubjectPublicKeyInfo containing the key.
     */
    SubjectPublicKeyInfo getPublicKey(String keyID);

    /**
     * Return our part of the public key identified by keyID.
     *
     * @param keyID the key ID of interest.
     * @return a SubjectPublicKeyInfo containing the key.
     */
    PartialPublicKeyInfo getPartialPublicKey(String keyID);

    /**
     * Return true if this node contains a share in the private key identified by keyID.
     *
     * @param keyID  the key ID of interest.
     * @return true if node contains keyID, false otherwise.
     */
    boolean hasPrivateKey(String keyID);

    /**
     * Return the operator associated with the private key represented by keyID.
     *
     * @param keyID the keyID we want the operator for.
     * @return a PrivateKeyOperator for keyID.
     */
    PrivateKeyOperator getPrivateKeyOperator(String keyID);

    /**
     * Shutdown the node, waiting no longer than time timeUnits.
     *
     * @param time the amount of units of time to wait.
     * @param timeUnit the magnitude of a time unit.
     * @return true if shutdown successfully, false otherwise.
     * @throws InterruptedException if interrupted while waiting.
     */
    boolean shutdown(int time, TimeUnit timeUnit)
        throws InterruptedException;

    /**
     * Return true if the node's executors are in the process of shutting down.
     *
     * @return true if the node is shutting down, false otherwise.
     */
    boolean isStopCalled();

    /**
     * Use the multi-tasking thread pool to execute the passed in task.
     *
     * @param task the task to execute.
     */
    void execute(Runnable task);

    /**
     * Schedule a task on the muilt-tasking thread pool after the specified delay.
     *
     * @param task the task to schedule.
     * @param time the number of time units to delay the task.
     * @param timeUnit the magnitude of a time unit.
     */
    void schedule(Runnable task, long time, TimeUnit timeUnit);

    /**
     * Return the executor associated with a particular decoupler.
     *
     * @param decouplerType the type of the decoupler requested.
     * @return the decoupler of the requested type, null if not present.
     */
    Executor getDecoupler(Decoupler decouplerType);

    /**
     * Return the multi-threaded scheduler for this context.
     *
     * @return the multi-threaded scheduler associated with this node context.
     */
    ScheduledExecutorService getScheduledExecutorService();

    /**
     * Return the executor service associated with this node.
     *
     * @return an ExecutorService.
     */
    ExecutorService getExecutorService();

    /**
     * Return the threshold key pair generator for the requested algorithm,
     *
     * @param algorithm the algorithm of interest.
     * @return a ThresholdKeyPairGenerator.
     */
    ThresholdKeyPairGenerator getKeyPairGenerator(Algorithm algorithm);

    /**
     * Return the name of the node hosting the specified board.
     *
     * @param boardName the name of the board of interest.
     * @return the name of the host holding the board.
     */
    String getBoardHost(String boardName);

    /**
     * Return the home directory of the node.
     *
     * @return the node's home directory.
     */
    File getHomeDirectory();

    /**
     * Return a Map of statistical objects for this node as name value pairs.
     *
     * @return a Map of statistical objects.
     */
    Map<NodeService,Map<String,Object>> getServiceStatistics();

    /**
     * Return a general description about this node.
     *
     * @return the nodes description.
     */
    Map<String,String> getDescription();

    /**
     * Return our ServerSocket details.
     *
     * @return the details about the ServerSocket we are using.
     */
    ListeningSocketInfo getListeningSocketInfo();

    /**
     * Return the event notifier for this node context. The
     * event notifier is used to log events of various levels as they occur.
     *
     * @return the event notifier for this node.
     */
    EventNotifier getEventNotifier();
}
