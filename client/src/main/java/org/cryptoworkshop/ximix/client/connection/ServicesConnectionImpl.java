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
package org.cryptoworkshop.ximix.client.connection;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

/**
 * Internal implementation of a general ServicesConnection. Unlike a NodeServicesConnection this class addresses the
 * Ximix network as a whole and will choose the first available suitable node for processing a message.
 */
class ServicesConnectionImpl
    implements ServicesConnection
{
    private final EventNotifier eventNotifier;
    private final NodeConnectionListener nodeConnectionListener;
    private final CountDownLatch isActivated = new CountDownLatch(1);
    private final List<NodeServicesConnection> connections = new ArrayList<>();
    private final List<NodeServicesConnection> adminConnections = new ArrayList<>();
    private final List<NodeServicesConnection> backupConnections = new ArrayList<>();

    private volatile NodeServicesConnection connection;
    private volatile NodeServicesConnection adminConnection;
    private volatile NodeServicesConnection backupConnection;

    public ServicesConnectionImpl(List<NodeConfig> configList, Executor decoupler, EventNotifier eventNotifier)
    {
        ListenerHandler<EventNotifier> notifierHandler = new DecoupledListenerHandlerFactory(decoupler, eventNotifier).createHandler(EventNotifier.class);
        notifierHandler.addListener(eventNotifier);
        this.eventNotifier = notifierHandler.getNotifier();

        ListenerHandler<NodeConnectionListener> listenerHandler = new DecoupledListenerHandlerFactory(decoupler, eventNotifier).createHandler(NodeConnectionListener.class);
        listenerHandler.addListener(new NodeConnectionListener()
        {
            @Override
            public void status(String name, boolean isAvailable)
            {
                // TODO: need to add code here to swap out a dead node for a live one
            }
        });
        this.nodeConnectionListener = listenerHandler.getNotifier();

        //
        // find a node to connect to
        //
        for (int i = 0; i != configList.size(); i++)
        {
            NodeConfig nodeConf = configList.get(i);

            if (nodeConf.getThrowable() == null)
            {
                connections.add(new NodeServicesConnection(nodeConf, nodeConnectionListener, eventNotifier));
                adminConnections.add(new NodeServicesConnection(nodeConf, nodeConnectionListener, eventNotifier));
                backupConnections.add(new NodeServicesConnection(nodeConf, nodeConnectionListener, eventNotifier));
            }
            else
            {
                eventNotifier.notify(EventNotifier.Level.ERROR, "Exception processing services connection config: " + nodeConf.getThrowable().getMessage(), nodeConf.getThrowable());
            }
        }
    }

    @Override
    public void shutdown()
        throws ServiceConnectionException
    {
        connection.shutdown();
        adminConnection.shutdown();
        backupConnection.shutdown();
    }

    @Override
    public void activate()
        throws ServiceConnectionException
    {
        try
        {
            // we have a choice so choose one
            if (connections.size() > 1)
            {
                // start at a random point in the list
                int start = new Random().nextInt();

                for (int i = 0; i != connections.size(); i++)
                {
                    int nodeNo = (start + i) % connections.size();

                    try
                    {
                        connection = connections.get(nodeNo);
                        adminConnection = adminConnections.get(nodeNo);
                        backupConnection = backupConnections.get(nodeNo);

                        connection.activate();
                        adminConnection.activate();
                        backupConnection.activate();
                        return;
                    }
                    catch (Exception e)
                    {
                        // try again...
                    }
                }

                // none are currently working, we'll just have to make the best of it.
                connection = connections.get(0);
                adminConnection = adminConnections.get(0);
                backupConnection = backupConnections.get(0);
            }
            else
            {
                // if we end up here, there's only one
                connection = connections.get(0);
                connection.activate();
                adminConnection = adminConnections.get(0);
                adminConnection.activate();
                backupConnection = backupConnections.get(0);
                backupConnection.activate();
            }
        }
        finally
        {
            isActivated.countDown();
        }
    }

    public CapabilityMessage[] getCapabilities()
    {
        try
        {
            isActivated.await();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }

        try
        {
            return connection.getCapabilities();
        }
        catch (Exception e)
        {
            return new CapabilityMessage[0];
        }
    }

    @Override
    public EventNotifier getEventNotifier()
    {
        return eventNotifier;
    }

    public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
        throws ServiceConnectionException
    {
        try
        {
            isActivated.await();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }

        // keep admin info messages on a separate channel.
        if (type == CommandMessage.Type.NODE_INFO_UPDATE || type == CommandMessage.Type.NODE_STATISTICS)
        {
            return adminConnection.sendMessage(type, messagePayload);
        }
        else if (type == CommandMessage.Type.BACKUP_BOARD_CREATE || type == CommandMessage.Type.TRANSFER_TO_BACKUP_BOARD || type == CommandMessage.Type.CLEAR_BACKUP_BOARD)
        {
            return backupConnection.sendMessage(type, messagePayload);
        }
        else
        {
            return connection.sendMessage(type, messagePayload);
        }
    }
}
