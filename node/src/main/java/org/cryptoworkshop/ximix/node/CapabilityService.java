package org.cryptoworkshop.ximix.node;

import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.Service;

/**
 *  The capabilities service.
 */
public class CapabilityService implements Service
{

    public CapabilityService() {

    }

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
    public boolean isAbleToHandle(Enum type)
    {
        return false;
    }
}
