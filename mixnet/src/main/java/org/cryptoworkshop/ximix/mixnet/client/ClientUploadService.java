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
package org.cryptoworkshop.ximix.mixnet.client;

import org.cryptoworkshop.ximix.common.handlers.ThrowableHandler;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.UploadMessage;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

public class ClientUploadService
    implements UploadService
{
    private ServicesConnection connection;


    public ClientUploadService(ServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public void close(ThrowableHandler handler)
    {
        this.connection.close(handler);
    }

    public void uploadMessage(String boardName, byte[] message)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(ClientMessage.Type.UPLOAD_TO_BOARD, new UploadMessage(boardName, message));

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed");
        }
    }
}
