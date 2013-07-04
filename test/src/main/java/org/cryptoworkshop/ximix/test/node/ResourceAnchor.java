package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;

/**
 *
 */
public class ResourceAnchor
{
    public static Config load(String path)
        throws ConfigException
    {
        return new Config(ResourceAnchor.class.getResourceAsStream(path));
    }

}
