/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.node.mixnet.service;

import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.node.service.BasicService;
import org.cryptoworkshop.ximix.node.service.NodeContext;

public class RemoteBoardHostingService
    extends BasicService
{
    private final String nodeName;
    private final CapabilityMessage capabilityMessage;

    public RemoteBoardHostingService(NodeContext nodeContext, String nodeName, CapabilityMessage capabilityMessage)
    {
        super(nodeContext);

        this.nodeName = nodeName;
        this.capabilityMessage = capabilityMessage;
    }

    public CapabilityMessage getCapability()
    {
        return capabilityMessage;
    }

    public MessageReply handle(Message message)
    {
        try
        {
            return nodeContext.getPeerMap().get(nodeName).sendMessage((MessageType)message.getType(), message.getPayload());
        }
        catch (ServiceConnectionException e)
        {
            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String(e.toString()));
        }
    }

    public boolean isAbleToHandle(Message message)
    {
        return new MessageEvaluator(capabilityMessage).isAbleToHandle(message);
    }
}
