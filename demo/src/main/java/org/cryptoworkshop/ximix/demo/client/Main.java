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
package org.cryptoworkshop.ximix.demo.client;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.service.XimixRegistrar;
import org.cryptoworkshop.ximix.service.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.upload.UploadService;
import org.cryptoworkshop.ximix.crypto.SigningService;

public class Main
{
    public static ECPoint generatePoint(ECDomainParameters params, SecureRandom rand)
    {
        return params.getG().multiply(getRandomInteger(params.getN(), rand));
    }

    public static BigInteger getRandomInteger(BigInteger n, SecureRandom rand)
    {
        BigInteger r;
        int maxbits = n.bitLength();
        do
        {
            r = new BigInteger(maxbits, rand);
        }
        while (r.compareTo(n) >= 0);
        return r;
    }

    public static void main(String[] args)
        throws Exception
    {
        SHA256Digest sha256 = new SHA256Digest();

        XimixRegistrar registrar = XimixRegistrarFactory.createServicesRegistrar(new File(args[0]));

        UploadService client = registrar.connect(UploadService.class);
        SigningService signingService = registrar.connect(SigningService.class);

        byte[] encPubKey = signingService.fetchPublicKey("ENCKEY");

        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);

        ECPoint candidate1 = generatePoint(pubKey.getParameters(), new SecureRandom());

        ECPoint candidate2 = generatePoint(pubKey.getParameters(), new SecureRandom());

        //
        // encrypt two candidate numbers
        //
        ECPair encCandidate1 = encryptor.encrypt(candidate1);
        ECPair encCandidate2 = encryptor.encrypt(candidate2);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        bOut.write(encCandidate1.getEncoded());
        bOut.write(encCandidate2.getEncoded());

        byte[] message = bOut.toByteArray();
        byte[] hash = new byte[sha256.getDigestSize()];

        sha256.update(message, 0, message.length);

        sha256.doFinal(hash, 0);

        //
        // append signature of encrypted message to upload message
        //
        byte[] dsaSig = signingService.generateSignature("SIGKEY", hash);

        bOut.write(dsaSig);

        client.uploadMessage("FRED", bOut.toByteArray());
    }
}
