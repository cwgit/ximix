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
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.cryptoworkshop.ximix.common.message.CreateSignatureMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceContext;

public class NodeSigningService
    implements Service
{
    Map<String, AsymmetricCipherKeyPair> keyMap = new HashMap<String, AsymmetricCipherKeyPair>();

    public NodeSigningService(ServiceContext nodeConnection)
    {
        //To change body of created methods use File | Settings | File Templates.
    }

    private SubjectPublicKeyInfo fetchPublicKey(String keyID)
        throws IOException
    {
        AsymmetricCipherKeyPair kp = getKeyPair(keyID);

        if (kp == null)
        {
            return null;
        }

        return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic());
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

    public MessageReply handle(Message message)
    {
        switch (message.getType())
        {
        case FETCH_PUBLIC_KEY:
            FetchPublicKeyMessage fetchMessage = FetchPublicKeyMessage.getInstance(message.getPayload());
             System.err.println("here") ;
            try
            {
                return new MessageReply(MessageReply.Type.OKAY, fetchPublicKey(fetchMessage.getKeyID()));
            }
            catch (IOException e)
            {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        case CREATE_SIGNATURE:
            CreateSignatureMessage sigMessage = CreateSignatureMessage.getInstance(message.getPayload());

            return new MessageReply(MessageReply.Type.OKAY, new DEROctetString(generateSignature(sigMessage.getKeyID(), sigMessage.getHash())));
        default:
            System.err.println("unknown command");
        }
        return null;  // TODO:
    }

    public boolean isAbleToHandle(Message.Type type)
    {
        return type == Message.Type.FETCH_PUBLIC_KEY || type == Message.Type.CREATE_SIGNATURE;
    }
}
