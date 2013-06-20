package org.cryptoworkshop.ximix.console;

import org.cryptoworkshop.ximix.console.util.Traversal;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class NodeManager
{

    private static NodeManager nodeManager = new NodeManager();

    private List<NodeAdapter> nodes = new ArrayList<NodeAdapter>();

    public static NodeManager manager()
    {
        return nodeManager;
    }

    void addNodeAdapter(NodeAdapter adapter)
    {
        if (nodes.contains(adapter))
        {
            throw new IllegalArgumentException("Already added.");
        }
        nodes.add(adapter);
    }

    /**
     * Traverse the list of nodes.
     *
     * @param adapters The adapter.
     */
    void nodes(Traversal<NodeAdapter> adapters)
    {
        for (NodeAdapter na : nodes)
        {
            adapters.element(na);
        }
    }


}
