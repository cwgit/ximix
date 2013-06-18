package org.cryptoworkshop.ximix.console;

import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.console.util.Traversal;

import java.util.List;

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

    void init(Object source) throws Exception;

}
