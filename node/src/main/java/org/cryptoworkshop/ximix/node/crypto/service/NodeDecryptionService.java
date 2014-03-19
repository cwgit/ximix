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

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequenceWithProofs;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageDataBlock;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.crypto.ECDecryptionProof;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.crypto.operator.ECPrivateKeyOperator;
import org.cryptoworkshop.ximix.node.service.BasicNodeService;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;

/**
 * Service class for perform decryption operations in a node.
 */
public class NodeDecryptionService
    extends BasicNodeService
{
    /**
     * Base constructor.
     *
     * @param nodeContext the context for the node we are in.
     * @param config source of config information if required.
     */
    public NodeDecryptionService(NodeContext nodeContext, Config config)
    {
        super(nodeContext);
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

            ProofGenerator pGen = new ProofGenerator(ecOperator, new SecureRandom()); // TODO: randomness

            for (int i = 0; i != messages.size(); i++)
            {
                PairSequence ps = PairSequence.getInstance(domainParameters.getCurve(), messages.get(i));
                ECPair[] pairs = ps.getECPairs();
                ECDecryptionProof[] proofs = new ECDecryptionProof[pairs.length];

                for (int j = 0; j != pairs.length; j++)
                {
                    ECPoint c = pairs[j].getX();
                    pairs[j] = new ECPair(ecOperator.transform(pairs[j].getX()), pairs[j].getY());

                    proofs[j] = pGen.computeProof(c, pairs[j]);
                }

                try
                {
                    partialDecryptsBuilder.add(new PairSequenceWithProofs(pairs, proofs).getEncoded());
                }
                catch (IOException e)
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Error encoding decrypt: " + e.getMessage(), e);

                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Error encoding decrypt: "  + e.getMessage()));
                }
            }

            return new MessageReply(MessageReply.Type.OKAY, new ShareMessage(operator.getSequenceNo(), partialDecryptsBuilder.build()));
        default:
            nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Unknown command: " + message.getType());

            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command: " + message.getType()));
        }
    }

    public boolean isAbleToHandle(Message message)
    {
        return message.getType() == CommandMessage.Type.PARTIAL_DECRYPT;
    }
}
