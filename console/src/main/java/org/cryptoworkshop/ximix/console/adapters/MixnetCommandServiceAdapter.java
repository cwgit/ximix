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

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.console.annotations.CommandParam;
import org.cryptoworkshop.ximix.common.console.annotations.ConsoleCommand;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;
import org.cryptoworkshop.ximix.mixnet.admin.MixnetCommandService;
import org.cryptoworkshop.ximix.mixnet.admin.NodeDetail;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;
import org.w3c.dom.Node;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * An adapter for the Mixnet commands service.
 */
public class MixnetCommandServiceAdapter
        extends BaseNodeAdapter
{

    protected File configFile = null;
    protected XimixRegistrar registrar = null;
    protected MixnetCommandService commandService = null;
    protected Class commandType = MixnetCommandService.class;
    protected Config config = null;


    public MixnetCommandServiceAdapter()
    {
        super();
    }


//    @Override
//    public void init(String name, Config config)
//            throws Exception
//    {
//        this.id = name;
//        this.config = config;
//        // this.configFile = new File(config.getProperty("config.file"));
//        commandList = new ArrayList<>();
//        findCommands(this);
//    }

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
    public void init(Config config, Node configRoot) throws Exception
    {
        commandList = new ArrayList<>();
        super.init(config, configRoot);
        Node nl = Config.getNodeOf(configRoot.getChildNodes(),"adapter-config");
        configFile = new File(Config.getValueOf(nl.getChildNodes(),"config-file"));
        findCommands(this);
    }

    @Override
    public void open()
            throws Exception
    {
        try
        {
            registrar = XimixRegistrarFactory.createAdminServiceRegistrar(configFile);
            commandService = registrar.connect(MixnetCommandService.class);
        } catch (Exception ex)
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

    @ConsoleCommand(name = "Do Shuffle & Move")
    public StandardMessage doShuffleAndMove(
            @CommandParam(name = "Board Name")
            String boardName,
            @CommandParam(name = "Transform Name")
            String transformName,
            @CommandParam(name = "Key id")
            String keyID,
            @CommandParam(name = "Nodes")
            String... nodes)
            throws ServiceConnectionException
    {

        //TODO add sensitisation.


        commandService.doShuffleAndMove(boardName, new ShuffleOptions.Builder(transformName, keyID).build(), nodes);

        return new StandardMessage(true, "It worked..");


    }

    @Override
    public List<NodeDetail> getNodeInfo()
    {

        //
        // The following may seem like overkill but it allows us to
        //

        //  try {

        ArrayList<NodeDetail> details = new ArrayList<>();

        details.add(new NodeDetail(1234, "Node 1"));
        details.add(new NodeDetail(1234, "Node 2"));
        details.add(new NodeDetail(1234, "Node 3"));
        details.add(new NodeDetail(1234, "Node 4"));


        //  List<NodeDetail> details = commandService.getNodeDetails();

        return details;


        //  } catch (ServiceConnectionException e) {
        //      e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        //  }


        // return null;
    }

}
