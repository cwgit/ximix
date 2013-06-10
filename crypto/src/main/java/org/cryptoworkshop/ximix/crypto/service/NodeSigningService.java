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
package org.cryptoworkshop.ximix.crypto.service;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CreateSignatureMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;

public class NodeSigningService
    implements Service
{
    private final NodeContext nodeContext;

    public NodeSigningService(NodeContext nodeContext, Config config)
    {
        this.nodeContext = nodeContext;
    }

    public byte[] generateSignature(String keyID, byte[] hash)
    {
        // TODO: needs to be distributed
        ECDSASigner signer = new ECDSASigner();

        try
        {
            CipherParameters privKey = nodeContext.getPrivateKey(keyID);

            signer.init(true, privKey);

            BigInteger[] rs = signer.generateSignature(hash);

            ASN1EncodableVector v = new ASN1EncodableVector();

             v.add(new ASN1Integer(rs[0]));
             v.add(new ASN1Integer(rs[1]));

            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            // TODO: some sort of sig failure exception will be required here...
        }

        return null;
    }

    public Capability getCapability()
    {
        return new Capability(Capability.Type.SIGNING, new String[] { " "}); // TODO:
    }

    public MessageReply handle(Message message)
    {
        switch (((ClientMessage)message).getType())
        {
        case CREATE_SIGNATURE:
            CreateSignatureMessage sigMessage = CreateSignatureMessage.getInstance(message.getPayload());

            return new MessageReply(MessageReply.Type.OKAY, new DEROctetString(generateSignature(sigMessage.getKeyID(), sigMessage.getHash())));
        default:
            System.err.println("unknown command");
        }
        return null;  // TODO:
    }

    public boolean isAbleToHandle(Enum type)
    {
        return type == ClientMessage.Type.CREATE_SIGNATURE;
    }
}
