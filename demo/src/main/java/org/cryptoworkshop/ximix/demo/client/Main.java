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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.board.asn1.PairSequence;
import org.cryptoworkshop.ximix.crypto.client.KeyService;
import org.cryptoworkshop.ximix.crypto.client.SigningService;
import org.cryptoworkshop.ximix.mixnet.client.UploadService;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

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

    public static BigInteger[] decodeSig(
        byte[] encoding)
        throws IOException
    {
        ASN1Sequence s = ASN1Sequence.getInstance(encoding);
        BigInteger[] sig = new BigInteger[2];

        sig[0] = ((ASN1Integer)s.getObjectAt(0)).getValue();
        sig[1] = ((ASN1Integer)s.getObjectAt(1)).getValue();

        return sig;
    }

    public static void main(String[] args)
        throws Exception
    {
        XimixRegistrar registrar = XimixRegistrarFactory.createServicesRegistrar(new File(args[0]));

        KeyService    keyFetcher = registrar.connect(KeyService.class);
        UploadService client = registrar.connect(UploadService.class);

        byte[] encPubKey = keyFetcher.fetchPublicKey("ECKEY");

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

        PairSequence ballot = new PairSequence(encCandidate1, encCandidate2);

        client.uploadMessage("FRED", ballot.getEncoded());
    }
}
