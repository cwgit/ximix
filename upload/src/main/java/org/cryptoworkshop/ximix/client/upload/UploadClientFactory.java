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
package org.cryptoworkshop.ximix.client.upload;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.conf.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.messages.Command;
import org.cryptoworkshop.ximix.common.messages.UploadMessage;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class UploadClientFactory
{
    public static UploadClient createClient(File config)
        throws ConfigException, UploadClientCreationException
    {
        List<NodeConfig> nodes = new Config(config).getConfigObjects("node", new NodeConfigFactory());

        //
        // find a MixNet node to connect to
        //
        // TODO: this should start at a random point in the list
        int start = 0;
        for (int i = 0; i != nodes.size(); i++)
        {
            int nodeNo = (start + i) % nodes.size();
            NodeConfig nodeConf = nodes.get(nodeNo);

            if (nodeConf.getThrowable() == null)
            {
                try
                {
                    final Socket connection = new Socket(nodeConf.getAddress(), nodeConf.getPortNo());

                    final OutputStream cOut = connection.getOutputStream();
                    final InputStream cIn = connection.getInputStream();

                    return new UploadClient()
                    {
                        Map<String, AsymmetricCipherKeyPair> keyMap = new HashMap<String, AsymmetricCipherKeyPair>();

                        public AsymmetricKeyParameter fetchPublicKey(String keyID)
                        {
                            // TODO: obviously this needs to take place remotely!
                            AsymmetricCipherKeyPair kp = getKeyPair(keyID);

                            return kp.getPublic();
                        }

                        private AsymmetricCipherKeyPair getKeyPair(String keyID)
                        {
                            AsymmetricCipherKeyPair kp = keyMap.get(keyID);

                            if (kp == null)
                            {
                                X9ECParameters params = SECNamedCurves.getByName("secp256r1");

                                ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

                                kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()), new SecureRandom()));

                                kp =  kpGen.generateKeyPair();

                                keyMap.put(keyID, kp);
                            }
                            return kp;
                        }

                        public byte[] generateSignature(String keyID, byte[] hash)
                        {
                            // TODO: needs to be distributed
                            ECDSASigner signer = new ECDSASigner();

                            AsymmetricCipherKeyPair kp = getKeyPair(keyID);

                            signer.init(true, kp.getPrivate());

                            BigInteger[] rs = signer.generateSignature(hash);

                            ASN1EncodableVector v = new ASN1EncodableVector();

                             v.add(new ASN1Integer(rs[0]));
                             v.add(new ASN1Integer(rs[1]));

                            try
                            {
                                return new DERSequence(v).getEncoded(ASN1Encoding.DER);
                            }
                            catch (IOException e)
                            {
                                // TODO: some sort of sig failure exception will be required here...
                            }

                            return null;
                        }

                        public void uploadMessage(String boardName, byte[] message)
                            throws IOException
                        {
                            cOut.write(new Command(Command.Type.UPLOAD_TO_BOARD, new UploadMessage(boardName, message)).getEncoded());

                            cIn.read();
                        }
                    };
                }
                catch (Exception e)
                {
                    // ignore
                }
            }
        }

        throw new UploadClientCreationException("Unable to find a client to connect to");
    }

    private static class NodeConfig
    {
        private InetAddress address;
        private int portNo;
        private Exception throwable;

        NodeConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                if (xmlNode.getNodeName().equals("host"))
                {
                    try
                    {
                        address = InetAddress.getByName(xmlNode.getTextContent());
                    }
                    catch (UnknownHostException e)
                    {
                        throwable = e;
                    }
                }
                else if (xmlNode.getNodeName().equals("portNo"))
                {
                    portNo = Integer.parseInt(xmlNode.getTextContent());
                }
            }
        }

        public Throwable getThrowable()
        {
            return throwable;
        }

        public InetAddress getAddress()
        {
            return address;
        }

        public int getPortNo()
        {
            return portNo;
        }
    }

    private static class NodeConfigFactory
        implements ConfigObjectFactory<NodeConfig>
    {
        public NodeConfig createObject(Node configNode)
        {
            return new NodeConfig(configNode);
        }
    }
}
