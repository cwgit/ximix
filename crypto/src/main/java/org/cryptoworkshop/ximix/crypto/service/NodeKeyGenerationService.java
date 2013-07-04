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

import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.common.message.ECKeyGenParams;
import org.cryptoworkshop.ximix.common.message.GenerateKeyPairMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.StoreSecretShareMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

public class NodeKeyGenerationService
    implements Service
{
    private final NodeContext nodeContext;

    public NodeKeyGenerationService(NodeContext nodeContext, Config config)
    {
        this.nodeContext = nodeContext;
    }

    public Capability getCapability()
    {
        return new Capability(Capability.Type.KEY_GENERATION, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(Message message)
    {
        // TODO: sort out the reply messages
        try
        {
            switch (((CommandMessage)message).getType())
            {
                case INITIATE_GENERATE_KEY_PAIR:
                    final GenerateKeyPairMessage initiateMessage = GenerateKeyPairMessage.getInstance(message.getPayload());
                    final Set<String> peersToInitiate = initiateMessage.getNodesToUse();

                    if (initiateMessage.getNodesToUse().contains(nodeContext.getName()))
                    {
                        //
                        // generate our part
                        //
                        ECCommittedSecretShareMessage[] messages = nodeContext.generateThresholdKey(initiateMessage.getKeyID(), peersToInitiate, initiateMessage.getThreshold(), initiateMessage.getKeyGenParameters());

                        //
                        // start everyone else
                        //

                        nodeContext.scheduleTask(new InitiateKeyGenTask(initiateMessage));

                        //
                        // send our shares.
                        //
                        nodeContext.scheduleTask(new SendShareTask(initiateMessage.getKeyID(), peersToInitiate, messages));
                    }

                    return new MessageReply(MessageReply.Type.OKAY, nodeContext.getPublicKey(initiateMessage.getKeyID()));
                case GENERATE_KEY_PAIR:
                    final GenerateKeyPairMessage generateMessage = GenerateKeyPairMessage.getInstance(message.getPayload());
                    final Set<String> involvedPeers = generateMessage.getNodesToUse();

                    if (involvedPeers.contains(nodeContext.getName()))
                    {
                        ECKeyGenParams ecKeyGenParams = (ECKeyGenParams)generateMessage.getKeyGenParameters();
                        ECCommittedSecretShareMessage[] messages = nodeContext.generateThresholdKey(generateMessage.getKeyID(), involvedPeers, generateMessage.getThreshold(), ecKeyGenParams);

                        nodeContext.scheduleTask(new SendShareTask(generateMessage.getKeyID(), involvedPeers, messages));
                    }

                    return new MessageReply(MessageReply.Type.OKAY);
                case STORE_SHARE:
                    final StoreSecretShareMessage sssMessage = StoreSecretShareMessage.getInstance(message.getPayload());
                    final ECCommittedSecretShareMessage shareMessage = ECCommittedSecretShareMessage.getInstance(nodeContext.<ECDomainParameters>getDomainParameters(sssMessage.getKeyID()).getCurve(), sssMessage.getSecretShareMessage());
                    System.err.println("Store: " + nodeContext.getName());
                    // we may not have been asked to generate our share yet, if this is the case we need to queue up our share requests
                    // till we can validate them.
                    nodeContext.scheduleTask(new StoreShareTask(sssMessage.getKeyID(), shareMessage));

                    return new MessageReply(MessageReply.Type.OKAY);
                default:
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeKeyGenerationService."));
            }
        }
        catch (Exception e)
        {
            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("NodeKeyGenerationService failure: " + e.getMessage()));
        }

    }

    public boolean isAbleToHandle(Enum type)
    {
        return type == CommandMessage.Type.INITIATE_GENERATE_KEY_PAIR
            || type == CommandMessage.Type.GENERATE_KEY_PAIR
            || type == CommandMessage.Type.STORE_SHARE;
    }

    private class InitiateKeyGenTask
        implements Runnable
    {
        private final GenerateKeyPairMessage initiateMessage;
        private final Set<String> peersToInitiate;

        InitiateKeyGenTask(GenerateKeyPairMessage initiateMessage)
        {
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
                        MessageReply rep = nodeContext.getPeerMap().get(name).sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, initiateMessage);
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
        private final String keyID;
        private final Set<String> peers;
        private final ECCommittedSecretShareMessage[] messages;

        SendShareTask(String keyID, Set<String> peers, ECCommittedSecretShareMessage[] messages)
        {
            this.keyID = keyID;
            this.peers = peers;
            this.messages = messages;
        }

        public void run()
        {
            int index = 0;
            for (final String name : peers)
            {
                System.err.println("sending: " + nodeContext.getName() + " to " + name);
                if (name.equals(nodeContext.getName()))
                {
                    nodeContext.storeThresholdKeyShare(keyID, messages[index++]);
                }
                else
                {
                    final int counter = index++;
                    nodeContext.getScheduledExecutor().schedule(new Runnable()
                    {
                        public void run()
                        {
                            try
                            {
                                MessageReply rep = nodeContext.getPeerMap().get(name).sendMessage(CommandMessage.Type.STORE_SHARE, new StoreSecretShareMessage(keyID, messages[counter]));
                            }
                            catch (ServiceConnectionException e)
                            {
                                e.printStackTrace(); // TODO handle.
                            }
                        }
                    }, 2000, TimeUnit.MILLISECONDS);  //TODO make configurable.

                }
            }
        }
    }

    private class StoreShareTask
        implements Runnable
    {
        private final String keyID;
        private final ECCommittedSecretShareMessage message;

        StoreShareTask(String keyID, ECCommittedSecretShareMessage message)
        {
            this.keyID = keyID;
            this.message = message;
        }

        @Override
        public void run()
        {
            if (nodeContext.hasPrivateKey(keyID))
            {
                nodeContext.storeThresholdKeyShare(keyID, message);
            }
            else
            {
                // TODO: there needs to be a limit on how long we do this!
                nodeContext.scheduleTask(StoreShareTask.this);
            }
        }
    }
}
