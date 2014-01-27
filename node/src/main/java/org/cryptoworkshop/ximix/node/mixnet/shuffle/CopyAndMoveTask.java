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
package org.cryptoworkshop.ximix.node.mixnet.shuffle;

import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadBlockMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CopyAndMoveMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.asn1.message.TransitBoardMessage;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.node.service.NodeContext;

/**
 * The basic copy to a new node task.
 */
public class CopyAndMoveTask
    implements Runnable
{
    private final NodeContext nodeContext;
    private final CopyAndMoveMessage message;
    private final BulletinBoardRegistry boardRegistry;
    private final ServicesConnection peerConnection;

    /**
     * Base constructor.
     *
     * @param nodeContext the context of the node this task is running in.
     * @param boardRegistry the registry for the boards on this node.
     * @param peerConnection a ServicesConnection to the node the board is to be moved to.
     * @param message the message carrying the instructions for the copy and move.
     */
    public CopyAndMoveTask(NodeContext nodeContext, BulletinBoardRegistry boardRegistry, ServicesConnection peerConnection, CopyAndMoveMessage message)
    {
        this.nodeContext = nodeContext;
        this.boardRegistry = boardRegistry;
        this.peerConnection = peerConnection;
        this.message = message;
    }

    public void run()
    {
        BulletinBoard board = boardRegistry.getBoard(message.getBoardName());

        try
        {
            PostedMessageBlock.Builder messageBlockBuilder = new PostedMessageBlock.Builder(20);    // TODO: make configurable

            for (PostedMessage postedMessage : board)
            {
                messageBlockBuilder.add(postedMessage.getIndex(), postedMessage.getMessage());

                if (messageBlockBuilder.isFull())
                {
                    processMessageBlock(messageBlockBuilder, message.getStepNumber());
                }
            }

            if (!messageBlockBuilder.isEmpty())
            {
                processMessageBlock(messageBlockBuilder, message.getStepNumber());
            }

            MessageReply reply = peerConnection.sendMessage(CommandMessage.Type.TRANSFER_TO_BOARD_ENDED, new TransitBoardMessage(message.getOperationNumber(), board.getName(), message.getStepNumber()));

            if (reply.getType() != MessageReply.Type.OKAY)
            {
                throw new ServiceConnectionException("message failed");
            }
        }
        catch (ServiceConnectionException e)
        {
            e.printStackTrace();
            // TODO: log?
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private void processMessageBlock(PostedMessageBlock.Builder messageBlockBuilder, int nextStepNumber)
        throws ServiceConnectionException
    {
        MessageReply reply = peerConnection.sendMessage(CommandMessage.Type.TRANSFER_TO_BOARD, new BoardUploadBlockMessage(message.getOperationNumber(), message.getBoardName(), nextStepNumber, messageBlockBuilder.build()));

        messageBlockBuilder.clear();

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed");
        }
    }
}
