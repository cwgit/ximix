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
package org.cryptoworkshop.ximix.node.mixnet.board;

import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.asn1.message.BoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadIndexedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.service.NodeContext;

public class BoardRemoteBackupListener
    implements BulletinBoardBackupListener
{
    private final NodeContext nodeContext;
    private final String backUpHost;

    public BoardRemoteBackupListener(NodeContext nodeContext, String backUpHost)
    {
        this.nodeContext = nodeContext;
        this.backUpHost = backUpHost;
    }

    public String getBackupHost()
    {
        return backUpHost;
    }

    @Override
    public void cleared(final BulletinBoard bulletinBoard)
    {
        nodeContext.getExecutorService().execute(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    MessageReply reply = nodeContext.getPeerMap().get(backUpHost).sendMessage(CommandMessage.Type.CLEAR_BACKUP_BOARD, new BoardMessage(bulletinBoard.getName()));
                    checkForError(reply);
                }
                catch (ServiceConnectionException e)
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Exception on clear backup.", e);
                }
            }
        });
    }

    @Override
    public void messagePosted(final BulletinBoard bulletinBoard, final int index, final byte[] message)
    {
        // TODO: there needs to be an initialisation phase to make sure the backup board is in sync
        nodeContext.getExecutorService().execute(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    MessageReply reply = nodeContext.getPeerMap().get(backUpHost).sendMessage(CommandMessage.Type.TRANSFER_TO_BACKUP_BOARD, new BoardUploadIndexedMessage(bulletinBoard.getName(), index, message));
                    checkForError(reply);
                }
                catch (ServiceConnectionException e)
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Exception on post to backup.", e);
                }
            }
        });
    }

    @Override
    public void messagesPosted(final BulletinBoard bulletinBoard, final int startIndex, final byte[][] messages)
    {
                    // TODO: there needs to be an initialisation phase to make sure the backup board is in sync
        nodeContext.getExecutorService().execute(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {

                    MessageReply reply = nodeContext.getPeerMap().get(backUpHost).sendMessage(CommandMessage.Type.TRANSFER_TO_BACKUP_BOARD, new BoardUploadIndexedMessage(bulletinBoard.getName(), startIndex, messages));
                    checkForError(reply);
                }
                catch (ServiceConnectionException e)
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Exception on post to backup.", e);
                }
            }
        });
    }

    private void checkForError(MessageReply reply)
    {
        if (reply == null)
        {
            nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Error on post to backup: null message received");
        }
        else if (reply.getType() != MessageReply.Type.OKAY)
        {
            String message = (reply.getPayload() instanceof DERUTF8String) ? DERUTF8String.getInstance(reply.getPayload()).getString() : "no detail";

            nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Error on post to backup: " + message);
        }
    }
}
