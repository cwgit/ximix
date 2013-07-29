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

    NodeStatusMessage getLastStatistics(String node);


    List<NodeStatusMessage> getConnectedNodeInfo()
        throws ServiceConnectionException;

    NodeStatusMessage getFullInfo()
        throws ServiceConnectionException;

}
