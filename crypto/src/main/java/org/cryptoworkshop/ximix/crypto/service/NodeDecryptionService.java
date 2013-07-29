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

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.cryptoworkshop.ximix.common.board.asn1.PairSequence;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.PostedMessageDataBlock;
import org.cryptoworkshop.ximix.common.message.ShareMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.PrivateKeyOperator;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.crypto.operator.ECPrivateKeyOperator;

public class NodeDecryptionService
    implements Service
{
    private final NodeContext nodeContext;

    public NodeDecryptionService(NodeContext nodeContext, Config config)
    {
        this.nodeContext = nodeContext;
    }

    public CapabilityMessage getCapability()
    {
        return new CapabilityMessage(CapabilityMessage.Type.DECRYPTION, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(Message message)
    {
        switch (((CommandMessage)message).getType())
        {
        case PARTIAL_DECRYPT:
            DecryptDataMessage decMessage = DecryptDataMessage.getInstance(message.getPayload());
            List<byte[]>       messages = decMessage.getMessages();
            PostedMessageDataBlock.Builder  partialDecryptsBuilder = new PostedMessageDataBlock.Builder(messages.size());

            PrivateKeyOperator operator = nodeContext.getPrivateKeyOperator(decMessage.getKeyID());

            if (!(operator instanceof ECPrivateKeyOperator))
            {
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Inappropriate key type"));
            }

            ECPrivateKeyOperator ecOperator = (ECPrivateKeyOperator)operator;

            ECDomainParameters domainParameters = ecOperator.getDomainParameters();

            for (int i = 0; i != messages.size(); i++)
            {
                PairSequence ps = PairSequence.getInstance(domainParameters.getCurve(), messages.get(i));
                ECPair[] pairs = ps.getECPairs();
                for (int j = 0; j != pairs.length; j++)
                {
                    pairs[j] = new ECPair(ecOperator.transform(pairs[j].getX()), pairs[j].getY());
                }
                try
                {
                    partialDecryptsBuilder.add(new PairSequence(pairs).getEncoded());
                }
                catch (IOException e)
                {
                    e.printStackTrace();  //TOOD: log
                }
            }

            return new MessageReply(MessageReply.Type.OKAY, new ShareMessage(operator.getSequenceNo(), partialDecryptsBuilder.build()));
        default:
            System.err.println("unknown command");
        }
        return null;  // TODO:
    }

    public boolean isAbleToHandle(Message message)
    {
        return message.getType() == CommandMessage.Type.PARTIAL_DECRYPT;
    }
}
