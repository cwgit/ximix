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
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.cryptoworkshop.ximix.common.board.asn1.PairSequence;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.message.MessageBlock;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;

public class NodeDecryptionService
    implements Service
{
    private final NodeContext nodeContext;

    public NodeDecryptionService(NodeContext nodeContext, Config config)
    {
        this.nodeContext = nodeContext;
    }

    public Capability getCapability()
    {
        return new Capability(Capability.Type.SIGNING, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(Message message)
    {
        switch (((CommandMessage)message).getType())
        {
        case PARTIAL_DECRYPT:
            DecryptDataMessage decMessage = DecryptDataMessage.getInstance(message.getPayload());
            List<byte[]>       messages = decMessage.getMessages();
            List<byte[]>       partialDecrypts = new ArrayList<>(messages.size());

            ECDomainParameters domainParameters = nodeContext.getDomainParameters(decMessage.getKeyID());

            for (int i = 0; i != messages.size(); i++)
            {
                PairSequence ps = PairSequence.getInstance(domainParameters.getCurve(), messages.get(i));
                ECPair[] pairs = ps.getECPairs();
                for (int j = 0; j != pairs.length; j++)
                {
                    pairs[j] = new ECPair(nodeContext.performPartialDecrypt(decMessage.getKeyID(), pairs[j].getX()), pairs[j].getY());
                }
                try
                {
                    partialDecrypts.add(new PairSequence(pairs).getEncoded());
                }
                catch (IOException e)
                {
                    e.printStackTrace();  //TOOD: log
                }
            }

            return new MessageReply(MessageReply.Type.OKAY, new MessageBlock(partialDecrypts));
        default:
            System.err.println("unknown command");
        }
        return null;  // TODO:
    }

    public boolean isAbleToHandle(Enum type)
    {
        return type == CommandMessage.Type.PARTIAL_DECRYPT;
    }
}
