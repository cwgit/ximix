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
package org.cryptoworkshop.ximix.client.connection;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Factory class to allow building of services connection maps. Normally just used for inter-node communication.
 */
public class XimixConnectionMapFactory
{
    /**
     * Create a map of ServicesConnection objects for the passed in Ximix configuration config.
     *
     *
     * @param config Ximix configuration to use.
     * @param eventNotifier event notifier to use in case of error.
     * @return a map of ServicesConnection objects representing handles to each node in the network.
     * @throws ConfigException if there is an error in the configuration.
     */
    public static Map<String, ServicesConnection> createServicesConnectionMap(Config config, EventNotifier eventNotifier)
        throws ConfigException
    {
        final List<NodeConfig> nodes = config.getConfigObjects("node", new NodeConfigFactory());

        return createServicesConnectionMap(nodes, eventNotifier);
    }

    private static Map<String, ServicesConnection> createServicesConnectionMap(List<NodeConfig> nodes, EventNotifier eventNotifier)
    {
        Map<String, ServicesConnection> rMap = new HashMap<>();

        for (int i = 0; i != nodes.size(); i++)
        {
            NodeConfig node = nodes.get(i);

            final String name = node.getName();
            final List<NodeConfig> thisNode = Collections.singletonList(node);

            rMap.put(name, new ServicesConnectionImpl(thisNode, eventNotifier));
        }

        return rMap;
    }
}
