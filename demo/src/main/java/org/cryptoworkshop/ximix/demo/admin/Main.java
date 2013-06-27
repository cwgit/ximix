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
package org.cryptoworkshop.ximix.demo.admin;

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.operation.Operation;
import org.cryptoworkshop.ximix.crypto.client.KeyGenerationService;
import org.cryptoworkshop.ximix.mixnet.DownloadOptions;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;
import org.cryptoworkshop.ximix.mixnet.admin.CommandService;
import org.cryptoworkshop.ximix.mixnet.admin.DownloadOperationListener;
import org.cryptoworkshop.ximix.mixnet.admin.ShuffleOperationListener;
import org.cryptoworkshop.ximix.common.board.asn1.PairSequence;
import org.cryptoworkshop.ximix.mixnet.client.UploadService;
import org.cryptoworkshop.ximix.mixnet.transform.MultiColumnRowTransform;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

public class Main
{
    private static ECPoint generatePoint(ECDomainParameters params, SecureRandom rand)
    {
        return params.getG().multiply(getRandomInteger(params.getN(), rand));
    }

    private static BigInteger getRandomInteger(BigInteger n, SecureRandom rand)
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
        SecureRandom random = new SecureRandom();

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(new File(args[0]));

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", 2, "A", "B");

        UploadService client = adminRegistrar.connect(UploadService.class);

        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);

        // set up 100 random messages
        ECPoint[] plainText = new ECPoint[100];
        for (int i = 0; i != plainText.length; i++)
        {
            plainText[i] = generatePoint(pubKey.getParameters(), random);

            PairSequence encrypted = new PairSequence(encryptor.encrypt(plainText[i]));

            client.uploadMessage("FRED", encrypted.getEncoded());
        }

        CommandService commandService = adminRegistrar.connect(CommandService.class);

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents("FRED", new DownloadOptions.Builder().setKeyID("ECKEY").setThreshold(2).build(), new DownloadOperationListener()
        {

            @Override
            public void messageDownloaded(byte[] message)
            {
                System.err.println("message downloaded!!!");
            }

            @Override
            public void completed()
            {
                System.err.println("completed");
            }

            @Override
            public void failed(String errorObject)
            {
                System.err.println("failed");
            }
        });
    }
}
