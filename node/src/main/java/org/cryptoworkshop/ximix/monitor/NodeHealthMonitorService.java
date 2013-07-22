package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.Service;

/**
 *
 */
public class NodeHealthMonitorService implements Service
{
    @Override
    public CapabilityMessage getCapability()
    {
        return null;
    }

    @Override
    public MessageReply handle(Message message)
    {
        return null;
    }

    @Override
    public boolean isAbleToHandle(Message message)
    {
        return false;
    }
}
