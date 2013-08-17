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
package org.cryptoworkshop.ximix.client.registrar;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;

public class XimixConnectionMapFactory
{
    /**
     * @param config
     * @return
     * @throws org.cryptoworkshop.ximix.common.config.ConfigException
     */
    public static Map<String, ServicesConnection> createServicesConnectionMap(Config config)
        throws ConfigException
    {
        final List<NodeConfig> nodes = config.getConfigObjects("node", new NodeConfigFactory());

        return createServicesConnectionMap(nodes);
    }

    private static Map<String, ServicesConnection> createServicesConnectionMap(List<NodeConfig> nodes)
    {
        Map<String, ServicesConnection> rMap = new HashMap<>();

        for (int i = 0; i != nodes.size(); i++)
        {
            NodeConfig node = nodes.get(i);

            final String name = node.getName();
            final List<NodeConfig> thisNode = Collections.singletonList(node);

            rMap.put(name, new ServicesConnectionImpl(thisNode));
        }

        return rMap;
    }
}
