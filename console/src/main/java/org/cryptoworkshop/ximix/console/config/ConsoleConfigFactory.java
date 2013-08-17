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
package org.cryptoworkshop.ximix.console.config;

import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Console config factory..
 */
public class ConsoleConfigFactory implements ConfigObjectFactory<ConsoleConfig>
{

    private static ConsoleConfigFactory factory = new ConsoleConfigFactory();

    public static ConsoleConfigFactory factory()
    {
        return factory;
    }

    @Override
    public ConsoleConfig createObject(Node configNode)
    {
        ConsoleConfig cfg = null;

        if ("console".equals(configNode.getNodeName()))
        {
            cfg = new ConsoleConfig();
            NodeList nl = configNode.getChildNodes();

            for (int t = 0; t < nl.getLength(); t++)
            {
                Node n = nl.item(t);
                if ("http".equals(n.getNodeName()))
                {
                    cfg.setHttpConfig(new HTTPConfig(n));
                    continue;
                } else if ("adapter".equals(n.getNodeName()))
                {
                    cfg.addAdapterConfig(new AdapterConfig(n));
                }
            }
        }

        return cfg;
    }


}
