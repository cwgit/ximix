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
package org.cryptoworkshop.ximix.mixnet.service;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Sequence;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.conf.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.BoardDetails;
import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MoveMessage;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.message.UploadMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.mixnet.task.TransformShuffleAndMoveTask;
import org.cryptoworkshop.ximix.mixnet.task.UploadTask;
import org.cryptoworkshop.ximix.mixnet.transform.Transform;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class BoardHostingService
    implements Service
{
    private final NodeContext serviceContext;
    private BulletinBoardRegistry boardRegistry = new BulletinBoardRegistry();

    public BoardHostingService(NodeContext context, Config config)
        throws ConfigException
    {
        this.serviceContext = context;

        final List<BoardConfig> boards = config.getConfigObjects("board", new BoardConfigFactory());

        for (BoardConfig boardConfig : boards)
        {
            boardRegistry.createBoard(boardConfig.getName(), boardConfig.getTransforms());
        }
    }

    public Capability getCapability()
    {
        String[] names = boardRegistry.getBoardNames();
        BoardDetails[] details = new BoardDetails[names.length];

        int count = 0;
        for (String name : names)
        {
            Transform[] transforms = boardRegistry.getBoard(name).getTransforms();
            Set<String> transformNames = new HashSet<String>();
            for (Transform transform : transforms)
            {
                transformNames.add(transform.getName());
            }

            details[count++] = new BoardDetails(name, transformNames);
        }

        return new Capability(Capability.Type.BOARD_HOSTING, details);
    }

    public MessageReply handle(Message message)
    {
        if (message instanceof CommandMessage)
        {
            switch (((CommandMessage)message).getType())
            {
            case ACTIVATE_BOARD:
                BoardMessage boardMessage = BoardMessage.getInstance(message.getPayload());
                boardRegistry.activateBoard(boardMessage.getBoardName());
                break;
            case SUSPEND_BOARD:
                boardMessage = BoardMessage.getInstance(message.getPayload());
                boardRegistry.suspendBoard(boardMessage.getBoardName());
                break;
            case SHUFFLE_AND_MOVE_BOARD_TO_NODE:
                PermuteAndMoveMessage pAndmMessage = PermuteAndMoveMessage.getInstance(message.getPayload());
                serviceContext.scheduleTask(new TransformShuffleAndMoveTask(serviceContext, boardRegistry, pAndmMessage));
                break;
            case TRANSFER_TO_BOARD:
                UploadMessage uploadMessage = UploadMessage.getInstance(message.getPayload());
                serviceContext.scheduleTask(new UploadTask(serviceContext, boardRegistry, uploadMessage));
                break;
            default:
                System.err.println("unknown command");
            }
        }
        else
        {
            switch (((ClientMessage)message).getType())
            {
            case UPLOAD_TO_BOARD:
                UploadMessage uploadMessage = UploadMessage.getInstance(message.getPayload());
                serviceContext.scheduleTask(new UploadTask(serviceContext, boardRegistry, uploadMessage));
                break;
            default:
                System.err.println("unknown command");
            }
        }
        return new MessageReply(MessageReply.Type.OKAY);
    }

    public boolean isAbleToHandle(Enum type)
    {
        return type == ClientMessage.Type.UPLOAD_TO_BOARD
            || type == CommandMessage.Type.SUSPEND_BOARD
            || type == CommandMessage.Type.ACTIVATE_BOARD
            || type == CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE
            || type == CommandMessage.Type.TRANSFER_TO_BOARD;
    }

    private static class BoardConfigFactory
        implements ConfigObjectFactory<BoardConfig>
    {
        public BoardConfig createObject(Node configNode)
        {
            return new BoardConfig(configNode);
        }
    }

    private static class BoardConfig
    {
        private String name;
        private Throwable throwable;
        private Map<String, Transform> transforms = new HashMap<String, Transform>();

        public BoardConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                if (xmlNode.getNodeName().equals("name"))
                {
                    this.name = xmlNode.getTextContent();
                }
                else if (xmlNode.getNodeName().equals("transform"))
                {
                    try
                    {
                        Class clazz = Class.forName(xmlNode.getTextContent().trim());

                        Constructor constructor = clazz.getConstructor();

                        Transform impl = (Transform)constructor.newInstance();

                        transforms.put(impl.getName(), impl);
                    }
                    catch (ClassNotFoundException e)
                    {
                        throwable = e;
                    }
                    catch (NoSuchMethodException e)
                    {
                        throwable = e;
                    }
                    catch (InvocationTargetException e)
                    {
                        throwable = e;
                    }
                    catch (InstantiationException e)
                    {
                        throwable = e;
                    }
                    catch (IllegalAccessException e)
                    {
                        throwable = e;
                    }
                }
            }
        }

        public String getName()
        {
            return name;
        }

        public Map<String, Transform> getTransforms()
        {
            return transforms;
        }
    }
}
