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
package org.cryptoworkshop.ximix.console;

import java.util.List;
import java.util.Map;

import org.cryptoworkshop.ximix.client.NodeDetail;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.console.config.AdapterConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.cryptoworkshop.ximix.console.model.Command;


/**
 * A basic interface to define a Node Adapter.
 */
public interface NodeAdapter
{


    /**
     * Open connection to node.
     */
    void open()
        throws Exception;

    /**
     * Close connection to the mode.
     */
    void close()
        throws Exception;

    /**
     * Initialise this adapter.
     *
     * @param consoleConfig The console configuration.
     * @param config        The adapter configuration.
     * @throws Exception rethrows all exceptions.
     */
    void init(ConsoleConfig consoleConfig, AdapterConfig config)
        throws Exception;

    /**
     * The details of this adapter.
     *
     * @return The details of this adapter.
     */
    AdapterInfo getInfo();

    /**
     * Command list.
     *
     * @return The command list.
     */
    List<Command> getCommandList();

    /**
     * Invoke a command on the adapter.
     *
     * @param id     The id.
     * @param params The params.
     * @return The response.
     */
    StandardMessage invoke(int id, Map<String, String[]> params);

    /**
     * The id.
     *
     * @return The id of the message.
     */
    String getId();

    /**
     * The name of the adapter.
     *
     * @return The name of the adabper.
     */

    String getName();

    /**
     * The adapters description.
     *
     * @return The description.
     */
    String getDescription();

    /**
     * Return a command name for an id.
     *
     * @param id The id.
     * @return The command id.
     */
    String getCommandNameForId(int id);

    /**
     * Is this adapter open.
     *
     * @return true = opened.
     */
    boolean isOpened();

    /**
     * Return a list of node details.
     *
     * @return The details of each node.
     */
    List<NodeStatusMessage.InfoMessage> getNodeDetails();

    /**
     * Return the statistics for a node.
     *
     * @param node The node.
     * @return The statistics object.
     */
    NodeStatusMessage getNodeStatistics(String node);

    /**
     * Return the details of each configured node.
     *
     * @return
     */
    List<NodeDetail> getConfiguredNodes();

    /**
     * Return the currently connected nodes.
     *
     * @return
     */
    List<NodeDetail> getConnectedNodes();

    /**
     * Return the detauls of each node.
     *
     * @param name
     * @return
     */
    NodeStatusMessage.InfoMessage getNodeDetails(String name);
}
