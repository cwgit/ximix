package org.cryptoworkshop.ximix.console.config;

import org.cryptoworkshop.ximix.common.conf.ConfigObjectFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Clonsol config factory..
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
