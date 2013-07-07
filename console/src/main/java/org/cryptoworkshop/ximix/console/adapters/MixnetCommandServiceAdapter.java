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

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.console.annotations.CommandParam;
import org.cryptoworkshop.ximix.common.console.annotations.ConsoleCommand;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.console.config.AdapterConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;
import org.cryptoworkshop.ximix.mixnet.admin.CommandService;
import org.cryptoworkshop.ximix.mixnet.admin.NodeDetail;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

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
    public void init(ConsoleConfig consoleConfig, AdapterConfig config) throws Exception
    {
        commandList = new ArrayList<>();
        super.init(consoleConfig, config);
        configFile = new File(config.get("config-file").toString());
        findCommands(this);
    }

    @Override
    public void open()
            throws Exception
    {
        try
        {
            registrar = XimixRegistrarFactory.createAdminServiceRegistrar(configFile);
            commandService = registrar.connect(CommandService.class);
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

        ShuffleOptions.Builder builder = new ShuffleOptions.Builder(transformName);
        builder.setKeyID(keyID);
        commandService.doShuffleAndMove(boardName, builder.build(), nodes);
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
