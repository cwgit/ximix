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
package org.cryptoworkshop.ximix.upload.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

import org.cryptoworkshop.ximix.common.message.Command;
import org.cryptoworkshop.ximix.common.message.UploadMessage;
import org.cryptoworkshop.ximix.upload.UploadService;

public class UploadServiceImpl
    implements UploadService
{
    private final InetAddress host;
    private final int portNo;

    private Socket connection;
    private OutputStream cOut;
    private InputStream cIn;

    public UploadServiceImpl(InetAddress host, int portNo)
        throws IOException
    {
        this.host = host;
        this.portNo = portNo;
        this.connection = new Socket(host, portNo);

       this.cOut = connection.getOutputStream();
       this.cIn = connection.getInputStream();


    }

    public void uploadMessage(String boardName, byte[] message)
        throws IOException
    {
        cOut.write(new Command(Command.Type.UPLOAD_TO_BOARD, new UploadMessage(boardName, message)).getEncoded());

        cIn.read();
    }
}
