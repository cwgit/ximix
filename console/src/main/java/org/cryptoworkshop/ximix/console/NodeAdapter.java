package org.cryptoworkshop.ximix.console;

import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.console.util.Config;
import org.cryptoworkshop.ximix.console.util.Traversal;
import org.cryptoworkshop.ximix.mixnet.admin.NodeDetail;

import java.util.List;
import java.util.Map;
import java.util.Properties;

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

    void init(String name, Config config) throws Exception;

    AdapterInfo getInfo();

    List<Command> getCommandList();

    List<NodeDetail> getNodeInfo();

    StandardMessage invoke(int id, Map<String, String[]> params);
}
