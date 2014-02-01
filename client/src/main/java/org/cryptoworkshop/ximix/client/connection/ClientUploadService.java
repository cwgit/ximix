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

import org.cryptoworkshop.ximix.client.UploadService;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;

/**
 * Internal implementation of the UploadService interface. This class creates the messages which are then sent down
 * the ServicesConnection.
 */
class ClientUploadService
    implements UploadService
{
    private ServicesConnection connection;


    public ClientUploadService(ServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public void shutdown() throws ServiceConnectionException
    {
        this.connection.close();
    }

    public void uploadMessage(String boardName, byte[] message)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(ClientMessage.Type.UPLOAD_TO_BOARD, new BoardUploadMessage(boardName, message));

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed: " + reply.interpretPayloadAsError());
        }
    }

    @Override
    public void uploadMessages(String boardName, byte[][] messages)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(ClientMessage.Type.UPLOAD_TO_BOARD, new BoardUploadMessage(boardName, messages));

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed: " + reply.interpretPayloadAsError());
        }
    }
}
