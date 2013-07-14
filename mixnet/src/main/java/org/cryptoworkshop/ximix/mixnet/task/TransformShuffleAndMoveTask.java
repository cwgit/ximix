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
package org.cryptoworkshop.ximix.mixnet.task;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.mixnet.transform.Transform;

public class TransformShuffleAndMoveTask
    implements Runnable
{
    private final NodeContext nodeContext;
    private final PermuteAndMoveMessage message;
    private final BulletinBoardRegistry boardRegistry;

    public TransformShuffleAndMoveTask(NodeContext nodeContext, BulletinBoardRegistry boardRegistry, PermuteAndMoveMessage message)
    {
        this.nodeContext = nodeContext;
        this.boardRegistry = boardRegistry;
        this.message = message;
    }

    public void run()
    {
        BulletinBoard board = boardRegistry.getTransitBoard(message.getBoardName());
        Transform transform = boardRegistry.getTransform(message.getTransformName());

        try
        {
            List<byte[]> transformedMessages = new ArrayList<byte[]>();

            if (message.getKeyID() != null)
            {
                transform.init(PublicKeyFactory.createKey(nodeContext.getPublicKey(message.getKeyID())));

                for (byte[] message : board)
                {
                    byte[] transformed = transform.transform(message);

                    transformedMessages.add(transformed);
                }
            }
            else
            {
                for (byte[] message : board)
                {
                    transformedMessages.add(message);
                }
            }

            ServicesConnection peerConnection = nodeContext.getPeerMap().get(message.getDestinationNode());

            for (byte[] message : transformedMessages)
            {
                MessageReply reply = peerConnection.sendMessage(CommandMessage.Type.TRANSFER_TO_BOARD, new BoardUploadMessage(board.getName(), message));

                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    throw new ServiceConnectionException("message failed");
                }
            }

            MessageReply reply = peerConnection.sendMessage(CommandMessage.Type.TRANSFER_TO_BOARD_ENDED, new BoardMessage(board.getName()));

            if (reply.getType() != MessageReply.Type.OKAY)
            {
                throw new ServiceConnectionException("message failed");
            }

            board.clear();
        }
        catch (ServiceConnectionException e)
        {
            // TODO: log?
        }
        catch (IOException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }
}
