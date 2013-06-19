package org.cryptoworkshop.ximix.console.adapters;

import org.cryptoworkshop.ximix.common.console.annotations.CommandParam;
import org.cryptoworkshop.ximix.common.console.annotations.ConsoleCommand;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.mixnet.admin.MixnetCommandService;
import org.cryptoworkshop.ximix.mixnet.admin.NodeDetail;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * An adapter for the Mixnet commands service.
 */
public class MixnetCommandServiceAdapter extends BaseNodeAdapter {

    protected File configFile = null;
    protected XimixRegistrar registrar = null;
    protected MixnetCommandService commandService = null;
    protected boolean isOpen = false;
    protected Class commandType = MixnetCommandService.class;


    public MixnetCommandServiceAdapter() {
        super();
    }

    public MixnetCommandServiceAdapter(File config) {
        super();
        this.configFile = config;
        commandList = new ArrayList<>();
    }


    public void init(Object source) throws Exception {

        if (source instanceof File) {
            configFile = (File) source;
        }

        findCommands(this.getClass());
    }

    @Override
    public void open() throws Exception {
        try {
            registrar = XimixRegistrarFactory.createAdminServiceRegistrar(configFile);
            commandService = registrar.connect(MixnetCommandService.class);
        } catch (Exception ex) {
            isOpen = false;
            throw new RuntimeException(ex); // TODO handle this better.
        }
    }

    @Override
    public void close() throws Exception {
        // TODO close it.
    }

    @ConsoleCommand(name = "Do Shuffles & Move")
    public StandardMessage doShuffleAndMove(
            @CommandParam(name = "Board Name")
            String boardName,
            @CommandParam(name = "Transform Name")
            String transformName,
            @CommandParam(name = "Key id")
            String keyID,
            @CommandParam(name = "Nodes")
            String... nodes)
            throws ServiceConnectionException {

        //TODO add sensitisation.


        //commandService.doShuffleAndMove(boardName, new ShuffleOptions.Builder(transformName, keyID).build(), nodes

        return new StandardMessage(true, "It worked.. not calling ximix method.");


    }

    public List<NodeDetail> getNodeInfo() {

        //
        // The following may seem like overkill but it allows us to
        //

      //  try {

            ArrayList<NodeDetail> details = new ArrayList<>();

            details.add(new NodeDetail(1234,"Central Node"));
            details.add(new NodeDetail(1234,"Lymph Node"));
            details.add(new NodeDetail(1234,"Borg Node"));
            details.add(new NodeDetail(1234,"Reference Node"));




            //  List<NodeDetail> details = commandService.getNodeDetails();

            return details;


      //  } catch (ServiceConnectionException e) {
      //      e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
      //  }


       // return null;
    }

}
