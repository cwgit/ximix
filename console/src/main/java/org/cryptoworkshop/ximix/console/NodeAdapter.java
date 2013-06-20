package org.cryptoworkshop.ximix.console;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.mixnet.admin.NodeDetail;
import org.w3c.dom.Node;


import java.util.List;
import java.util.Map;


/**
 * A basic interface to define a Node Adapter.
 */
public interface NodeAdapter {



    /**
     * Open connection to node.
     */
    void open() throws Exception;

    /**
     * Close connection to the mode.
     */
    void close() throws Exception;

    void init(Config config, Node configRoot) throws Exception;

    AdapterInfo getInfo();

    List<Command> getCommandList();

    List<NodeDetail> getNodeInfo();

    StandardMessage invoke(int id, Map<String, String[]> params);

    String getId();

    String getName();

    String getDescription();

    String getCommandNameForId(int id);
}
