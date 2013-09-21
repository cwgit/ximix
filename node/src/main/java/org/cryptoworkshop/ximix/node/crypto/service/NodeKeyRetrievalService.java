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
package org.cryptoworkshop.ximix.node.crypto.service;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPartialPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.node.service.BasicNodeService;
import org.cryptoworkshop.ximix.node.service.NodeContext;

public class NodeKeyRetrievalService
    extends BasicNodeService
{
    public NodeKeyRetrievalService(NodeContext nodeContext, Config config)
    {
        super(nodeContext);
    }

    public CapabilityMessage getCapability()
    {
        return new CapabilityMessage(CapabilityMessage.Type.KEY_RETRIEVAL, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(Message message)
    {
        if (message instanceof CommandMessage)
        {
            switch (((CommandMessage)message).getType())
            {
            case FETCH_PARTIAL_PUBLIC_KEY:
                FetchPartialPublicKeyMessage fetchMessage = FetchPartialPublicKeyMessage.getInstance(message.getPayload());

                return new MessageReply(MessageReply.Type.OKAY, nodeContext.getPartialPublicKey(fetchMessage.getKeyID()));
            default:
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeKeyGenerationService."));
            }
        }
        else
        {
            switch (((ClientMessage)message).getType())
            {
            case FETCH_PUBLIC_KEY:
                FetchPublicKeyMessage fetchMessage = FetchPublicKeyMessage.getInstance(message.getPayload());

                return new MessageReply(MessageReply.Type.OKAY, nodeContext.getPublicKey(fetchMessage.getKeyID()));
            default:
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown client command in NodeKeyGenerationService."));
            }
        }
    }

    public boolean isAbleToHandle(Message message)
    {
        return message.getType() == ClientMessage.Type.FETCH_PUBLIC_KEY || message.getType() == CommandMessage.Type.FETCH_PARTIAL_PUBLIC_KEY;
    }
}
