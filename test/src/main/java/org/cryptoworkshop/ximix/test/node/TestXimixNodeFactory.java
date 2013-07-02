package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.node.ThrowableHandler;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.XimixNodeFactory;
import org.cryptoworkshop.ximix.registrar.RegistrarConnectionException;

import java.util.Map;

/**
 *
 */
public class TestXimixNodeFactory extends XimixNodeFactory
{
    public static XimixNode createNode(Map<String, ServicesConnection> servicesMap, Config config, ThrowableHandler throwableHandler) throws RegistrarConnectionException, ConfigException
    {
        XimixNode node = new XimixNodeImpl(servicesMap, config);
        ((XimixNodeImpl) node).setUnhandledThrowableHandler(throwableHandler);
        return node;
    }


    public static XimixNode createNode(String servicesPath, String configPath, ThrowableHandler throwableHandler) throws RegistrarConnectionException, ConfigException
    {
        XimixNode node = XimixNodeFactory.createNode(TestXimixNodeFactory.class.getResourceAsStream(servicesPath), TestXimixNodeFactory.class.getResourceAsStream(configPath));
        ((XimixNodeImpl) node).setUnhandledThrowableHandler(throwableHandler);
        return node;
    }

}
