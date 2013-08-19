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
package org.cryptoworkshop.ximix.client;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

/**
 * Carrier interface for methods associated with node health and state monitoring.
 */
public interface MonitorService
{
    /**
     * Return a map of the details for all the nodes configured on the registrar this MonitorService is from.
     *
     * @return a map of node details, keyed by node name.
     */
    Map<String, NodeDetail> getConfiguredNodeDetails();

    /**
     * Return a set of the currently connected nodes that the registrar this MonitorService is from has available.
     *
     * @return a set of connected node names.
     */
    Set<String> getConnectedNodeNames();

    /**
     * Return the statistics and status for a particular node.
     *
     * @param node name of the node of interest.
     * @return the status and statistics for the node of interest.
     * @throws ServiceConnectionException in case of failure.
     */
    NodeStatusMessage.StatisticsMessage getStatistics(String node)
        throws ServiceConnectionException;

    /**
     * Return the statistics and status for all nodes.
     *
     * @return the status and statistics for all nodes.
     * @throws ServiceConnectionException in case of failure.
     */
    List<NodeStatusMessage.InfoMessage> getFullInfo()
        throws ServiceConnectionException;

    /**
     * Return the statistics and status for a particular node.
     *
     * @param node name of the node of interest.
     * @return the status and statistics for the node of interest.
     * @throws ServiceConnectionException in case of failure.
     */
    NodeStatusMessage.InfoMessage getFullInfo(String node)
        throws ServiceConnectionException;
}
