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
package org.cryptoworkshop.ximix.console.adapters;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.MonitorService;
import org.cryptoworkshop.ximix.client.NodeDetail;
import org.cryptoworkshop.ximix.client.RegistrarServiceException;
import org.cryptoworkshop.ximix.client.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.client.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.console.config.AdapterConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;

/**
 * An adapter for the Mixnet commands service.
 */
public class MixnetCommandServiceAdapter
    extends BaseNodeAdapter
{

    protected File configFile = null;
    protected XimixRegistrar registrar = null;
    protected CommandService commandService = null;
    protected Class commandType = CommandService.class;
    protected Config config = null;
    protected Map<String, NodeDetail> nameToConfig = null;

    public MixnetCommandServiceAdapter()
    {
        super();
    }


    @Override
    public AdapterInfo getInfo()
    {
        AdapterInfo info = new AdapterInfo();
        info.setId(id);
        info.setName(name);
        info.setDescription(description);
        return info;
    }

    @Override
    public void init(ConsoleConfig consoleConfig, AdapterConfig config)
        throws Exception
    {
        commandList = new ArrayList<>();
        super.init(consoleConfig, config);

        String f = config.get("mixnet-file").toString();
        if (f.isEmpty())
        {
            f = System.getProperty("mixnet-file");
        }

        if (f == null || f.isEmpty())
        {
            throw new RuntimeException("Mixnet file not specified.");
        }

        configFile = new File(f);
    }

    @Override
    public void open()
        throws Exception
    {
        try
        {                                      // TODO: put in something meaningful
            registrar = XimixRegistrarFactory.createAdminServiceRegistrar(configFile, new EventNotifier()
            {
                @Override
                public void notify(Level level, Throwable throwable)
                {
                    //To change body of implemented methods use File | Settings | File Templates.
                }

                @Override
                public void notify(Level level, Object detail)
                {
                    //To change body of implemented methods use File | Settings | File Templates.
                }

                @Override
                public void notify(Level level, Object detail, Throwable throwable)
                {
                    //To change body of implemented methods use File | Settings | File Templates.
                }
            });
            nameToConfig = registrar.connect(MonitorService.class).getConfiguredNodeDetails();
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex); // TODO handle this better.
        }

        opened = true;
    }

    @Override
    public void close()
        throws Exception
    {
        // TODO close it.
    }

    @Override
    public List<NodeDetail> getConfiguredNodes()
    {
        List nodes = new ArrayList();

        nodes.addAll(nameToConfig.values());

        return nodes;
    }

    @Override
    public List<NodeDetail> getConnectedNodes()
    {
        ArrayList<NodeDetail> out = new ArrayList<>();
        try
        {
            MonitorService nhm = registrar.connect(MonitorService.class);
            Set<String> names = nhm.getConnectedNodeNames();

            for (String n : names)
            {
                out.add(nameToConfig.get(n));
            }

        }
        catch (RegistrarServiceException e)
        {
            e.printStackTrace();
        }

        return out;
    }

    @Override
    public NodeStatusMessage getNodeDetails(String name)
    {
        NodeStatusMessage details = null;
        try
        {
            MonitorService nhm = registrar.connect(MonitorService.class);
            details = nhm.getFullInfo(name);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return details;
    }

    @Override
    public List<NodeStatusMessage.InfoMessage> getNodeDetails()
    {
        List<NodeStatusMessage.InfoMessage> details = null;
        try
        {
            MonitorService nhm = registrar.connect(MonitorService.class);
            details = nhm.getFullInfo();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return details;

    }

    @Override
    public NodeStatusMessage getNodeStatistics(String node)
    {
        NodeStatusMessage details = null;
        try
        {
            MonitorService nhm = registrar.connect(MonitorService.class);
            details = nhm.getStatistics(node);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return details;
    }

}
