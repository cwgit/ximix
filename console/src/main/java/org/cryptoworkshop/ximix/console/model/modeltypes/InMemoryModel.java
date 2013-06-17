package org.cryptoworkshop.ximix.console.model.modeltypes;

import org.cryptoworkshop.ximix.console.model.ConsoleModel;
import org.cryptoworkshop.ximix.common.console.model.NodeInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 *
 */
public class InMemoryModel extends ConsoleModel {
    private ConcurrentHashMap<String, NodeInfo> nodeNameToNodeInfo = new ConcurrentHashMap<>();
    private CopyOnWriteArrayList<NodeInfo> nodeInfos = new CopyOnWriteArrayList<>();

    public InMemoryModel() {
       addOrUpdate(new NodeInfo("Foo"));
       addOrUpdate(new NodeInfo("Bar"));
       addOrUpdate(new NodeInfo("Baz"));
    }

    @Override
    public void addOrUpdate(NodeInfo info) {
        if (info.getName() == null) {
            throw new IllegalArgumentException("NodeInfo name is null.");
        }



        NodeInfo old = nodeNameToNodeInfo.put(info.getName(), info);

        //
        // This is not expected to scale to more than a few (5) nodes.
        //

        if (old != null) {
            nodeInfos.remove(old);
        }
        nodeInfos.add(info);
    }


    @Override
    public List<NodeInfo> getNodeInfos() {
        {
            ArrayList<NodeInfo> out = new ArrayList<>();
            out.addAll(nodeInfos);
            for (NodeInfo ni: out)
            {
                ni.setHash(ni.getHostName().hashCode() ^ ni.getName().hashCode());
            }
            return out;

        }
    }
}
