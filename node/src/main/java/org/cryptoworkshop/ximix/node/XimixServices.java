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
package org.cryptoworkshop.ximix.node;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.NodeInfo;
import org.cryptoworkshop.ximix.common.service.Service;

class XimixServices
    implements Runnable
{
    private final Socket s;
    private final XimixNodeContext nodeContext;

    public XimixServices(XimixNodeContext nodeContext, Socket s)
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

            ASN1InputStream aIn = new ASN1InputStream(sIn, 32 * 1024);       // TODO: should be a config item
            DEROutputStream aOut = new DEROutputStream(sOut);

            aOut.writeObject(new NodeInfo(nodeContext.getName(), nodeContext.getCapabilities()));

            Object o;

            while ((o = aIn.readObject()) != null)
            {
                Message message = Message.getInstance(o);

                Service service = nodeContext.getService(message.getType());
                System.err.println("message received: " + message.getType() + " " + service);
                MessageReply reply = service.handle(message);

                System.err.println("message received: " + reply);
                aOut.writeObject(reply);
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }
}
