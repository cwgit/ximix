package org.cryptoworkshop.ximix.demo.lt;

import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.w3c.dom.Node;

/**
 *
 */
public class LoadTesterConfigFactory
    implements ConfigObjectFactory<LoadTesterConfig>
{
    @Override
    public LoadTesterConfig createObject(Node configNode)
    {
        return new LoadTesterConfig(configNode);
    }
}
