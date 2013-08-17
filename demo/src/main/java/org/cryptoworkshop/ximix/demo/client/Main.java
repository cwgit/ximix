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

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.engines.BLS01Signer;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.KeyService;
import org.cryptoworkshop.ximix.client.SignatureGenerationOptions;
import org.cryptoworkshop.ximix.client.SigningService;
import org.cryptoworkshop.ximix.client.XimixRegistrar;
import org.cryptoworkshop.ximix.client.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.node.crypto.key.util.BLSPublicKeyFactory;

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
        //UploadService client = registrar.connect(UploadService.class);
        SigningService signingService = registrar.connect(SigningService.class);

        byte[] encPubKey = keyFetcher.fetchPublicKey("ECENCKEY");

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

       // client.uploadMessage("FRED", ballot.getEncoded());

        SHA256Digest sha256 = new SHA256Digest();

        byte[] message = ballot.getEncoded();
        byte[] hash = new byte[sha256.getDigestSize()];

        sha256.update(message, 0, message.length);

        sha256.doFinal(hash, 0);

        //
        // ECDSA
        //
        SignatureGenerationOptions sigGenOptions = new SignatureGenerationOptions.Builder(Algorithm.ECDSA)
            .withThreshold(2)
            .withNodes("A", "B", "C", "D")
            .build();

        byte[] dsaSig = signingService.generateSignature("ECSIGKEY", sigGenOptions, hash);

        //
        // check the signature locally.
        //
        ECDSASigner signer = new ECDSASigner();

        ECPublicKeyParameters sigPubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(signingService.fetchPublicKey("ECSIGKEY"));

        signer.init(false, sigPubKey);

        BigInteger[] rs = decodeSig(dsaSig);

        if (signer.verifySignature(hash, rs[0], rs[1]))
        {
            System.out.println("sig verified!");
        }
        else
        {
            System.out.println("sig failed...");
        }

        SignatureGenerationOptions blsSigGenOptions = new SignatureGenerationOptions.Builder(Algorithm.BLS)
            .withThreshold(3)
            .withNodes("B", "C", "D")
            .build();

        byte[] blsSig = signingService.generateSignature("BLSSIGKEY", blsSigGenOptions, hash);

        //
        // check the signature locally.
        //
        BLS01Signer blsSigner = new BLS01Signer(sha256);

        BLS01PublicKeyParameters blsPubKey = BLSPublicKeyFactory.createKey(signingService.fetchPublicKey("BLSSIGKEY"));

        blsSigner.init(false, blsPubKey);

        blsSigner.update(message, 0, message.length);

        if (blsSigner.verifySignature(blsSig))
        {
            System.out.println("sig verified!");
        }
        else
        {
            System.out.println("sig failed...");
        }
    }
}
