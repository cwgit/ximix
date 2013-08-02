package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 *
 */
public interface NodeHealthMonitor
{

    NodeStatusMessage getStatistics(String node)
        throws ServiceConnectionException;


    List<NodeStatusMessage> getFullInfo()
        throws ServiceConnectionException;

    Set<String> getConnectedNodeNames();

    NodeStatusMessage getFullInfo(String name);

}
