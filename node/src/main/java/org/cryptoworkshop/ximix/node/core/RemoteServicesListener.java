package org.cryptoworkshop.ximix.node.core;

import org.cryptoworkshop.ximix.common.asn1.message.NodeInfo;

public interface RemoteServicesListener
{
    void nodeUpdate(NodeInfo nodeInfo);
}
