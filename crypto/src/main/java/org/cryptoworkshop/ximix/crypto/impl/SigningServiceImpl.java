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
package org.cryptoworkshop.ximix.crypto.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.cryptoworkshop.ximix.crypto.SigningService;

public class SigningServiceImpl
    implements SigningService
{
    Map<String, AsymmetricCipherKeyPair> keyMap = new HashMap<String, AsymmetricCipherKeyPair>();

    public byte[] fetchPublicKey(String keyID)
    {
        // TODO: obviously this needs to take place remotely!
        try
        {
            AsymmetricCipherKeyPair kp = getKeyPair(keyID);

            if (kp == null)
            {
                return null;
            }

            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()).getEncoded();
        }
        catch (IOException e)
        {
            // TODO: there's probably no point in telling the client more than this, but it does need to be logged remotely.
            return new byte[0];
        }
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
}
