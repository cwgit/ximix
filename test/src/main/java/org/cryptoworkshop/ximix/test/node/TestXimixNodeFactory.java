package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.node.ThrowableHandler;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.XimixNodeBuilder;
import org.cryptoworkshop.ximix.registrar.RegistrarConnectionException;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Map;

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
