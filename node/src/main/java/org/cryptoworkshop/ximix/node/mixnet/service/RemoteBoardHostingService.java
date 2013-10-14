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
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.node.service.BasicNodeService;
import org.cryptoworkshop.ximix.node.service.NodeContext;

/**
 * A proxy for a board hosting service on another machine.
 */
public class RemoteBoardHostingService
    extends BasicNodeService
{
    private final String nodeName;
    private final CapabilityMessage capabilityMessage;

    /**
     * Base constructor.
     *
     * @param nodeContext the context we are associated with.
     * @param nodeName the name of the node this proxy service represents.
     * @param capabilityMessage the board hosting capability of the node.
     */
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
