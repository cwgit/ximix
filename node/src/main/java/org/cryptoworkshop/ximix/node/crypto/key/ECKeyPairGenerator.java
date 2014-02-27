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
package org.cryptoworkshop.ximix.node.crypto.key;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.common.asn1.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ECPointMessage;
import org.cryptoworkshop.ximix.common.asn1.message.KeyPairGenerateMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.asn1.message.StoreMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.crypto.util.ECPointShare;
import org.cryptoworkshop.ximix.node.crypto.util.ShareMap;
import org.cryptoworkshop.ximix.node.service.Decoupler;
import org.cryptoworkshop.ximix.node.service.NodeContext;

/**
 * A generator for Elliptic Curve keys.
 */
public class ECKeyPairGenerator
    extends KeyPairGenerator
{
    private static final int MAX_ITERATIONS = 1000;      // if we can't generate a random number in the right subgroup in this many iterations, something is badly wrong

    private final Map<String, ECDomainParameters> paramsMap = Collections.synchronizedMap(new HashMap<String, ECDomainParameters>());
    private final ShareMap<String, ECPoint> sharedHMap;

    private final NodeContext nodeContext;

    public static enum Type
        implements MessageType
    {
        GENERATE,  // must always be first
        STORE_H,
        STORE
    }

    /**
     * Base constructor.
     *
     * @param nodeContext the node context this generator is associated with.
     */
    public ECKeyPairGenerator(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;

        this.sharedHMap = new ShareMap<>(nodeContext.getScheduledExecutorService(), nodeContext.getDecoupler(Decoupler.SHARING), nodeContext.getEventNotifier());
    }

    public CapabilityMessage getCapability()
    {
        return new CapabilityMessage(CapabilityMessage.Type.KEY_GENERATION, new ASN1Encodable[0]); // TODO: add algorithms?
    }

    public MessageReply handle(final KeyPairGenerateMessage message)
    {
        // TODO: sort out the reply messages
        try
        {
            switch (((Type)message.getType()))
            {
            case GENERATE:
                final NamedKeyGenParams ecKeyGenParams = (NamedKeyGenParams)NamedKeyGenParams.getInstance(message.getPayload());
                final List<String> involvedPeers = ecKeyGenParams.getNodesToUse();

                X9ECParameters params = CustomNamedCurves.getByName(ecKeyGenParams.getDomainParameters());

                if (params == null)
                {
                    params = ECNamedCurveTable.getByName(ecKeyGenParams.getDomainParameters());
                }

                paramsMap.put(ecKeyGenParams.getKeyID(), new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()));

                sharedHMap.init(ecKeyGenParams.getKeyID(), involvedPeers.size());

                BigInteger h = generateH(params.getN(), new SecureRandom());  // TODO: provide randomness?
                ECPoint[]    messages = new ECPoint[involvedPeers.size()];

                for (int i = 0; i != messages.length; i++)
                {
                    messages[i] = params.getG().multiply(h);
                }

                nodeContext.execute(new SendHTask(message.getAlgorithm(), ecKeyGenParams.getKeyID(), involvedPeers, messages));

                final List<String> peerList = ecKeyGenParams.getNodesToUse();

                ECNewDKGGenerator generator = (ECNewDKGGenerator)nodeContext.getKeyPairGenerator(ecKeyGenParams.getAlgorithm());

                ECCommittedSecretShareMessage[] comMessages = generator.generateThresholdKey(
                                                                          ecKeyGenParams.getKeyID(), paramsMap.get(ecKeyGenParams.getKeyID()), peerList.size(),
                                                                          ecKeyGenParams.getThreshold(), sharedHMap.getShare(ecKeyGenParams.getKeyID()).getValue().normalize());

                nodeContext.execute(new SendShareTask(generator, message.getAlgorithm(), ecKeyGenParams.getKeyID(), peerList, comMessages));

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE_H:
                StoreMessage storeMessage = StoreMessage.getInstance(message.getPayload());
                ShareMessage shareMessage = ShareMessage.getInstance(storeMessage.getSecretShareMessage());

                nodeContext.execute(new StoreHTask(storeMessage.getID(), shareMessage));

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE:
                StoreMessage sssMessage = StoreMessage.getInstance(message.getPayload());

                // we may not have been asked to generate our share yet, if this is the case we need to queue up our share requests
                // till we can validate them.
                generator = (ECNewDKGGenerator)nodeContext.getKeyPairGenerator(message.getAlgorithm());

                nodeContext.execute(new StoreShareTask(generator, sssMessage.getID(), sssMessage.getSecretShareMessage()));

                return new MessageReply(MessageReply.Type.OKAY);
            default:
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeKeyGenerationService."));
            }
        }
        catch (Exception e)
        {
            nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "NodeKeyGenerationService failure: " + e.getMessage(), e);

            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("NodeKeyGenerationService failure: " + e.getMessage()));
        }

    }

    private BigInteger generateH(BigInteger g, SecureRandom random)
        throws ServiceConnectionException
    {
        int gBitLength = g.bitLength();
        int count = 0;

        BigInteger k = null;
        do
        {
            if (count++ >= MAX_ITERATIONS)
            {
                break;
            }

            k = new BigInteger(gBitLength, random);
        }
        while (k.equals(BigInteger.ZERO) || k.compareTo(g) >= 0);

        if (count >= MAX_ITERATIONS)
        {
            throw new ServiceConnectionException("Unable to generate random values for key generation.");
        }

        return k;
    }

    private class SendHTask
        implements Runnable
    {
        private final String keyID;
        private final List<String> peers;
        private final ECPoint[] messages;
        private final Algorithm algorithm;

        SendHTask(Algorithm algorithm, String keyID, List<String> peers, ECPoint[] messages)
        {
            this.algorithm = algorithm;
            this.keyID = keyID;
            this.peers = peers;
            this.messages = messages;
        }

        public void run()
        {
            for (int i = 0; i != peers.size(); i++)
            {
                String name = peers.get(i);

                if (name.equals(nodeContext.getName()))
                {
                    sharedHMap.addValue(keyID, new ECPointShare(i + 1, messages[i]));
                }
                else
                {
                    nodeContext.execute(new SendHToNodeTask(name, keyID, algorithm, i + 1, messages[i]));
                }
            }
        }
    }

    private class SendHToNodeTask
        implements Runnable
    {
        private final String name;
        private final String keyID;
        private final Algorithm algorithm;
        private final int sequenceNo;
        private final ECPoint shareMessage;

        SendHToNodeTask(String name, String keyID, Algorithm algorithm, int sequenceNo, ECPoint shareMessage)
        {
            this.name = name;
            this.keyID = keyID;
            this.algorithm = algorithm;
            this.sequenceNo = sequenceNo;
            this.shareMessage = shareMessage;
        }

        public void run()
        {
            try
            {
                ServicesConnection connection = nodeContext.getPeerMap().get(name);
                if (connection != null)
                {
                    MessageReply rep = connection.sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR,
                        new AlgorithmServiceMessage(algorithm, new KeyPairGenerateMessage(algorithm, Type.STORE_H, new StoreMessage(keyID, new ShareMessage(sequenceNo, new ECPointMessage(shareMessage))))));
                    if (rep.getType() != MessageReply.Type.OKAY)
                    {
                        nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Error in SendShare: " + rep.interpretPayloadAsError());
                    }
                }
                else
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.WARN, "Node " + name + " not connected, waiting");

                    nodeContext.schedule(SendHToNodeTask.this, 2, TimeUnit.SECONDS);
                }
            }
            catch (ServiceConnectionException e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Exception in SendShareToNodeTask: " + e.getMessage(), e);
            }
        }
    }

    private class StoreHTask
        implements Runnable
    {
        private final String keyID;
        private final ShareMessage message;

        StoreHTask(String keyID, ShareMessage message)
        {
            this.keyID = keyID;
            this.message = message;
        }

        @Override
        public void run()
        {
            if (sharedHMap.containsKey(keyID))
            {
                sharedHMap.addValue(keyID, new ECPointShare(message.getSequenceNo(), ECPointMessage.getInstance(paramsMap.get(keyID).getCurve(), message.getShareData()).getPoint()));
            }
            else
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.WARN, "Still waiting for generate message for key " + keyID);

                nodeContext.schedule(StoreHTask.this, 1, TimeUnit.SECONDS);
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
                    nodeContext.execute(new SendShareToNodeTask(name, keyID, algorithm, messages[index++]));
                }
            }
        }
    }

    private class SendShareToNodeTask
        implements Runnable
    {
        private final String name;
        private final String keyID;
        private final Algorithm algorithm;
        private final ECCommittedSecretShareMessage shareMessage;

        SendShareToNodeTask(String name, String keyID, Algorithm algorithm, ECCommittedSecretShareMessage shareMessage)
        {
            this.name = name;
            this.keyID = keyID;
            this.algorithm = algorithm;
            this.shareMessage = shareMessage;
        }

        public void run()
        {
            try
            {
                ServicesConnection connection = nodeContext.getPeerMap().get(name);
                if (connection != null)
                {
                    MessageReply rep = connection.sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(algorithm, new KeyPairGenerateMessage(algorithm, Type.STORE, new StoreMessage(keyID, shareMessage))));
                    if (rep.getType() != MessageReply.Type.OKAY)
                    {
                        nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Error in SendShare: " + rep.interpretPayloadAsError());
                    }
                }
                else
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.WARN, "Node " + name + " not connected, waiting");
                    try
                    {
                        Thread.sleep(2000);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                    }
                    nodeContext.execute(SendShareToNodeTask.this);
                }
            }
            catch (ServiceConnectionException e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Exception in SendShareToNodeTask: " + e.getMessage(), e);
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
                nodeContext.getEventNotifier().notify(EventNotifier.Level.WARN, "Still waiting for generate message for key " + keyID);
                nodeContext.schedule(StoreShareTask.this, 1, TimeUnit.SECONDS);
            }
        }
    }
}
