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
package org.cryptoworkshop.ximix.crypto.service;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.crypto.key.ECKeyPairGenerator;
import org.cryptoworkshop.ximix.crypto.key.message.KeyPairGenerateMessage;

public class NodeKeyGenerationService
    implements Service
{
    private final NodeContext nodeContext;

    public NodeKeyGenerationService(NodeContext nodeContext, Config config)
    {
        this.nodeContext = nodeContext;
    }

    public CapabilityMessage getCapability()
    {
        return new CapabilityMessage(CapabilityMessage.Type.KEY_GENERATION, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(Message message)
    {
        // TODO: sort out the reply messages
        try
        {
            switch (((CommandMessage)message).getType())
            {
            case GENERATE_KEY_PAIR:
                return new ECKeyPairGenerator(nodeContext).handle(KeyPairGenerateMessage.getInstance(ECKeyPairGenerator.Type.values(), message.getPayload()));
            default:
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeKeyGenerationService."));
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("NodeKeyGenerationService failure: " + e.getMessage()));
        }

    }

    public boolean isAbleToHandle(Message message)
    {
        Enum type = message.getType();

        return type == CommandMessage.Type.GENERATE_KEY_PAIR
            || type == CommandMessage.Type.STORE_SHARE;
    }
}
