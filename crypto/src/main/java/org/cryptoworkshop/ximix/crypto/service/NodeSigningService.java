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
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.crypto.signature.ECDSASignerEngine;

public class NodeSigningService
    implements Service
{
    private final NodeContext nodeContext;

    private final ECDSASignerEngine ecdsaSignerEngine;

    public NodeSigningService(NodeContext nodeContext, Config config)
    {
        this.nodeContext = nodeContext;
        // TODO: make this configurable
        this.ecdsaSignerEngine = new ECDSASignerEngine(nodeContext);
    }

    public Capability getCapability()
    {
        return new Capability(Capability.Type.SIGNING, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(final Message message)
    {
        try
        {
            if (message.getType() instanceof ClientMessage.Type)
            {
                switch (((ClientMessage)message).getType())
                {
                case CREATE_SIGNATURE:
                    return ecdsaSignerEngine.handle(SignatureMessage.getInstance(ECDSASignerEngine.Type.values(), message.getPayload()));
                default:
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeSigningService."));
                }
            }
            else
            {
                switch (((CommandMessage)message).getType())
                {
                case SIGNATURE_MESSAGE:

                    SignatureMessage sigMessage = SignatureMessage.getInstance(ECDSASignerEngine.Type.values(), message.getPayload());

                    return ecdsaSignerEngine.handle(sigMessage);
                default:
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeSigningService."));
                }
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("NodeKeyGenerationService failure: " + e.getMessage()));
        }
    }

    public boolean isAbleToHandle(Enum type)
    {
        return type == ClientMessage.Type.CREATE_SIGNATURE || type == CommandMessage.Type.SIGNATURE_MESSAGE;
    }
}
