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
package org.cryptoworkshop.ximix.crypto.key;

import java.math.BigInteger;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.common.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.message.StoreMessage;
import org.cryptoworkshop.ximix.common.service.Algorithm;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.crypto.key.message.ECKeyGenParams;
import org.cryptoworkshop.ximix.common.message.KeyGenParams;
import org.cryptoworkshop.ximix.common.message.KeyGenerationMessage;
import org.cryptoworkshop.ximix.common.message.KeyPairGenerateMessage;

public class ECKeyPairGenerator
    extends KeyPairGenerator
{
    private final NodeContext nodeContext;

    public static enum Type
        implements MessageType
    {
        INITIATE,    // must always be first.
        GENERATE,
        STORE
    }

    public ECKeyPairGenerator(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;
    }

    public CapabilityMessage getCapability()
    {
        return new CapabilityMessage(CapabilityMessage.Type.KEY_GENERATION, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(KeyPairGenerateMessage message)
    {
        // TODO: sort out the reply messages
        try
        {
            switch (((Type)message.getType()))
            {
            case INITIATE:
                final KeyGenerationMessage initiateMessage = KeyGenerationMessage.getInstance(message.getPayload());

                if (initiateMessage.getNodesToUse().contains(nodeContext.getName()))
                {
                    KeyGenParams ecGenParams = KeyGenParams.getInstance(initiateMessage.getKeyGenParameters());

                    //
                    // Generate H, start everyone else      TODO generate H
                    //
                    ECNewDKGGenerator generator = (ECNewDKGGenerator)nodeContext.getKeyPairGenerator(initiateMessage.getAlgorithm());
                    ECKeyGenParams ecKeyGenParams = new ECKeyGenParams(initiateMessage.getKeyID(), message.getAlgorithm(), BigInteger.valueOf(1000001), ecGenParams.getDomainParameters(), initiateMessage.getThreshold(), initiateMessage.getNodesToUse());
                    ECCommittedSecretShareMessage[] messages = generator.generateThresholdKey(ecKeyGenParams.getKeyID(), ecKeyGenParams);

                    nodeContext.execute(new SendShareTask(generator, message.getAlgorithm(), ecKeyGenParams.getKeyID(), ecKeyGenParams.getNodesToUse(), messages));
                    nodeContext.execute(new InitiateKeyGenTask(message.getAlgorithm(), ecKeyGenParams));
                }
                else
                {
                    for (String node : initiateMessage.getNodesToUse())
                    {         // find first available
                        return nodeContext.getPeerMap().get(node).sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(message.getAlgorithm(), new KeyPairGenerateMessage(message.getAlgorithm(), Type.GENERATE, initiateMessage)));
                    }
                }

                return new MessageReply(MessageReply.Type.OKAY, nodeContext.getPublicKey(initiateMessage.getKeyID()));
            case GENERATE:
                final ECKeyGenParams ecKeyGenParams = (ECKeyGenParams)ECKeyGenParams.getInstance(message.getPayload());
                final List<String> involvedPeers = ecKeyGenParams.getNodesToUse();

                if (involvedPeers.contains(nodeContext.getName()))
                {
                    ECNewDKGGenerator generator = (ECNewDKGGenerator)nodeContext.getKeyPairGenerator(ecKeyGenParams.getAlgorithm());

                    ECCommittedSecretShareMessage[] messages = generator.generateThresholdKey(ecKeyGenParams.getKeyID(), ecKeyGenParams);

                    nodeContext.execute(new SendShareTask(generator, message.getAlgorithm(), ecKeyGenParams.getKeyID(), involvedPeers, messages));
                }

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE:
                StoreMessage sssMessage = StoreMessage.getInstance(message.getPayload());

                // we may not have been asked to generate our share yet, if this is the case we need to queue up our share requests
                // till we can validate them.
                ECNewDKGGenerator generator = (ECNewDKGGenerator)nodeContext.getKeyPairGenerator(message.getAlgorithm());

                nodeContext.execute(new StoreShareTask(generator, sssMessage.getID(), sssMessage.getSecretShareMessage()));

                return new MessageReply(MessageReply.Type.OKAY);
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

    private class InitiateKeyGenTask
        implements Runnable
    {
        private final ECKeyGenParams initiateMessage;
        private final List<String> peersToInitiate;
        private final Algorithm algorithm;

        InitiateKeyGenTask( Algorithm algorithm, ECKeyGenParams initiateMessage)
        {
            this.algorithm = algorithm;
            this.initiateMessage = initiateMessage;
            this.peersToInitiate = initiateMessage.getNodesToUse();
        }

        @Override
        public void run()
        {
            for (String name : peersToInitiate)
            {
                if (!name.equals(nodeContext.getName()))
                {
                    try
                    {
                        MessageReply rep = nodeContext.getPeerMap().get(name).sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(algorithm, new KeyPairGenerateMessage(algorithm, Type.GENERATE, initiateMessage)));
                    }
                    catch (ServiceConnectionException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                }
            }
        }
    }

    private class SendShareTask
        implements Runnable
    {
        private final ECNewDKGGenerator generator;
        private final String keyID;
        private final List<String> peers;
        private final ECCommittedSecretShareMessage[] messages;
        private final Algorithm algorithm;

        SendShareTask(ECNewDKGGenerator generator, Algorithm algorithm, String keyID, List<String> peers, ECCommittedSecretShareMessage[] messages)
        {
            this.generator = generator;
            this.algorithm = algorithm;
            this.keyID = keyID;
            this.peers = peers;
            this.messages = messages;
        }

        public void run()
        {
            int index = 0;

            for (final String name : peers)
            {
                if (name.equals(nodeContext.getName()))
                {
                    generator.storeThresholdKeyShare(keyID, messages[index++]);
                }
                else
                {
                    final int counter = index++;

                    nodeContext.execute(new Runnable()
                    {
                        public void run()
                        {
                            try
                            {
                                MessageReply rep = nodeContext.getPeerMap().get(name).sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(algorithm, new KeyPairGenerateMessage(algorithm, Type.STORE, new StoreMessage(keyID, messages[counter]))));
                            }
                            catch (ServiceConnectionException e)
                            {
                                e.printStackTrace(); // TODO handle.
                            }
                        }
                    });

                }
            }
        }
    }

    private class StoreShareTask
        implements Runnable
    {
        private final ECNewDKGGenerator generator;
        private final String keyID;
        private final ASN1Encodable message;

        StoreShareTask(ECNewDKGGenerator generator, String keyID, ASN1Encodable message)
        {
            this.generator = generator;
            this.keyID = keyID;
            this.message = message;
        }

        @Override
        public void run()
        {
            if (nodeContext.hasPrivateKey(keyID))
            {
                generator.storeThresholdKeyShare(keyID, ECCommittedSecretShareMessage.getInstance(generator.getParameters(keyID).getCurve(), message));
            }
            else
            {
                // TODO: there needs to be a limit on how long we do this!
                nodeContext.execute(StoreShareTask.this);
            }
        }
    }
}
