package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

import java.util.List;

/**
 *
 */
public interface NodeHealthMonitor
{

    NodeStatusMessage getLastStatistics(String node)
        throws ServiceConnectionException;


    List<NodeStatusMessage> getConnectedNodeInfo()
        throws ServiceConnectionException;

    NodeStatusMessage getFullInfo(String name)
        throws ServiceConnectionException;

}
