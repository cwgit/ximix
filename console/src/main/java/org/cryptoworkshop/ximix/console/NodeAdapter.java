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

import org.cryptoworkshop.ximix.console.config.AdapterConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.mixnet.admin.NodeDetail;


/**
 * A basic interface to define a Node Adapter.
 */
public interface NodeAdapter
{


    /**
     * Open connection to node.
     */
    void open() throws Exception;

    /**
     * Close connection to the mode.
     */
    void close() throws Exception;

    void init(ConsoleConfig consoleConfig,  AdapterConfig config) throws Exception;

    AdapterInfo getInfo();

    List<Command> getCommandList();

    List<NodeDetail> getNodeInfo();

    StandardMessage invoke(int id, Map<String, String[]> params);

    String getId();

    String getName();

    String getDescription();

    String getCommandNameForId(int id);

    boolean isOpened();
}
