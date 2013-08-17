package org.cryptoworkshop.ximix.test.node;

import java.io.File;
import java.io.FileNotFoundException;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.node.core.XimixNodeBuilder;

/**
 *
 */
public class TestXimixNodeFactory extends XimixNodeBuilder
{
    public TestXimixNodeFactory(Config peersConfig)
    {
        super(peersConfig);
    }

    public TestXimixNodeFactory(File file)
        throws ConfigException, FileNotFoundException
    {
        super(file);
    }


}
