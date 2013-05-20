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
package org.cryptoworkshop.ximix.mixnet;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.messages.Command;
import org.cryptoworkshop.ximix.common.messages.UploadMessage;
import org.cryptoworkshop.ximix.mixnet.task.UploadTask;

public class MixNetNodeFactory
{
    public static MixNetNode createNode(File config)
        throws ConfigException
    {
        final int portNo = new Config(config).getIntegerProperty("portNo");

        return new MixNetNode()
        {
            private final MixNetNodeContext nodeContext = new MixNetNodeContext();

            public void start()
            {
                boolean stop = false;

                try
                {
                    ServerSocket ss = new ServerSocket(portNo);

                    while (!stop)
                    {
                         Socket s = ss.accept();

                         nodeContext.addConnection(new NodeConnection(nodeContext, s));
                    }
                }
                catch (IOException e)
                {
                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }
            }
        };
    }

    private static class NodeConnection
        implements Runnable
    {
        private final Socket s;
        private final MixNetNodeContext nodeContext;

        public NodeConnection(MixNetNodeContext nodeContext, Socket s)
        {
            this.s = s;
            this.nodeContext = nodeContext;
        }

        public void run()
        {
            try
            {
                InputStream sIn = s.getInputStream();
                OutputStream sOut = s.getOutputStream();

                ASN1InputStream aIn = new ASN1InputStream(sIn, 32 * 1024);
                DEROutputStream aOut = new DEROutputStream(sOut);

                Object o;

                while ((o = aIn.readObject()) != null)
                {
                    Command com = Command.getInstance(o);

                    switch (com.getType())
                    {
                    case UPLOAD_TO_BOARD:
                        nodeContext.scheduleTask(new UploadTask(nodeContext, UploadMessage.getInstance(com.getPayload())));
                        break;
                    default:
                        System.err.println("unknown command");
                    }
                    System.err.println("message received");
                    aOut.writeObject(new DEROctetString(new byte[10]));
                }
            }
            catch (IOException e)
            {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }
    }
}
