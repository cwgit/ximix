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
package org.cryptoworkshop.ximix.mixnet.shuffle;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.commitments.HashCommitter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.BoardUploadBlockMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.message.PostedMessage;
import org.cryptoworkshop.ximix.common.message.PostedMessageBlock;
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
    private final CommandMessage.Type type;

    public TransformShuffleAndMoveTask(NodeContext nodeContext, BulletinBoardRegistry boardRegistry, CommandMessage.Type type, PermuteAndMoveMessage message)
    {
        this.nodeContext = nodeContext;
        this.boardRegistry = boardRegistry;
        this.type = type;
        this.message = message;
    }

    public void run()
    {
        BulletinBoard board = boardRegistry.getTransitBoard(message.getOperationNumber(), message.getBoardName(), message.getStepNumber());
        Transform transform = boardRegistry.getTransform(message.getTransformName());
        IndexCommitter committer = new IndexCommitter(new SHA256Digest(), new SecureRandom());

        try
        {
            ServicesConnection peerConnection = nodeContext.getPeerMap().get(message.getDestinationNode());
            PostedMessageBlock.Builder messageBlockBuilder = new PostedMessageBlock.Builder(20);                  // TODO: make configurable
            IndexNumberGenerator indexGen = new IndexNumberGenerator(board.size(), new SecureRandom());  // TODO: specify random

            int nextStepNumber = message.getStepNumber() + 1;

            if (message.getKeyID() != null)
            {
                transform.init(PublicKeyFactory.createKey(nodeContext.getPublicKey(message.getKeyID())));

                for (PostedMessage postedMessage : board)
                {
                    byte[] transformed = transform.transform(postedMessage.getMessage());

                    Commitment commitment = committer.commit(postedMessage.getIndex());

                    messageBlockBuilder.add(indexGen.nextIndex(), transformed, commitment.getCommitment());

                    if (messageBlockBuilder.isFull())
                    {
                        MessageReply reply = peerConnection.sendMessage(type, new BoardUploadBlockMessage(message.getOperationNumber(), message.getBoardName(), nextStepNumber, messageBlockBuilder.build()));

                        if (reply.getType() != MessageReply.Type.OKAY)
                        {
                            throw new ServiceConnectionException("message failed");
                        }
                    }
                }
            }
            else
            {
                for (PostedMessage postedMessage : board)
                {
                    Commitment commitment = committer.commit(postedMessage.getIndex());

                    messageBlockBuilder.add(postedMessage.getIndex(), postedMessage.getMessage(), commitment.getCommitment());

                    if (messageBlockBuilder.isFull())
                    {
                        MessageReply reply = peerConnection.sendMessage(type, new BoardUploadBlockMessage(message.getOperationNumber(), message.getBoardName(), nextStepNumber, messageBlockBuilder.build()));

                        if (reply.getType() != MessageReply.Type.OKAY)
                        {
                            throw new ServiceConnectionException("message failed");
                        }
                    }
                }
            }

            if (!messageBlockBuilder.isEmpty())
            {
                MessageReply reply = peerConnection.sendMessage(type, new BoardUploadBlockMessage(message.getOperationNumber(), board.getName(), nextStepNumber, messageBlockBuilder.build()));

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
            e.printStackTrace();
            // TODO: log?
        }
        catch (IOException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        catch (RuntimeException e)
        {
            e.printStackTrace();
        }
    }

    private class IndexCommitter
        extends HashCommitter
    {
        public IndexCommitter(ExtendedDigest digest, SecureRandom random)
        {
            super(digest, random);
        }

        public Commitment commit(int index)
        {
            return super.commit(BigInteger.valueOf(index).toByteArray());
        }
    }
}
