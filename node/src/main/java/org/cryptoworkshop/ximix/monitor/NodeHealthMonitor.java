package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

import java.util.List;

/**
 *
 */
public interface NodeHealthMonitor
{
    void resetToLast(int count, String... nodes)
        throws ServiceConnectionException;

    NodeStatusMessage getLast(String node);


    List<NodeStatusMessage> getConnectedNodeDetails()
        throws ServiceConnectionException;


}
