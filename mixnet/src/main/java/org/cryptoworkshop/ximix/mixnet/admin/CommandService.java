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
package org.cryptoworkshop.ximix.mixnet.admin;

import java.util.List;

import org.cryptoworkshop.ximix.common.handlers.ThrowableListener;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

public interface CommandService
    extends ShuffleOperation,
    DownloadOperation
{
    /**
     * Return a list of static details about the node.
     *
     * @return The node.
     * @throws ServiceConnectionException
     */
    List<NodeDetail> getNodeDetails()
        throws ServiceConnectionException;

    /**
     * Return a set of dynamic details about a node.
     *
     * @param nodes The nodes.
     * @return
     * @throws ServiceConnectionException
     */
    List<NodeHealth> getNodeHealth(String... nodes)
        throws ServiceConnectionException;

    /**
     * Return processing statistics about a node.
     *
     * @param nodes
     * @return
     */
    List<NodeStatistics> getNodeStatistics(String... nodes);

    /**
     * Cause nodes to shutdown.
     *
     * @param nodes
     */
    void shutdown(String... nodes);

    /**
     * Cause nodes to restart.
     *
     * @param nodes
     */
    void restart(String... nodes);

    /**
     * Close any io used by this service.
     */
    void shutdown() throws ServiceConnectionException;
}
