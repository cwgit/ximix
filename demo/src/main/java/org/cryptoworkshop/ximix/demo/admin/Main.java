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
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.DownloadOperationListener;
import org.cryptoworkshop.ximix.client.DownloadOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.ShuffleOperationListener;
import org.cryptoworkshop.ximix.client.ShuffleOptions;
import org.cryptoworkshop.ximix.client.UploadService;
import org.cryptoworkshop.ximix.client.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.client.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.operation.Operation;
import org.cryptoworkshop.ximix.mixnet.transform.MultiColumnRowTransform;

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

        byte[] encPubKey = keyGenerationService.fetchPublicKey("ECENCKEY");

        if (encPubKey == null)
        {
            KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.EC_ELGAMAL, "secp256r1")
                .withThreshold(2)
                .withNodes("A", "B", "C", "D")
                .build();

            encPubKey = keyGenerationService.generatePublicKey("ECENCKEY", keyGenOptions);
        }

        byte[] sigPubKey = keyGenerationService.fetchPublicKey("ECSIGKEY");

        if (sigPubKey == null)
        {
            KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.ECDSA, "secp256r1")
                                                       .withThreshold(2)
                                                       .withNodes("A", "B", "C", "D")
                                                       .build();


            sigPubKey = keyGenerationService.generatePublicKey("ECSIGKEY", keyGenOptions);
        }

        byte[] blsPubKey = keyGenerationService.fetchPublicKey("BLSSIGKEY");

        if (blsPubKey == null)
        {
            KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.BLS, "d62003-159-158.param")
                                                       .withThreshold(3)
                                                       .withNodes("A", "B", "C", "D")
                                                       .build();


            blsPubKey = keyGenerationService.generatePublicKey("BLSSIGKEY", keyGenOptions);
        }


        UploadService client = adminRegistrar.connect(UploadService.class);

        final ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        final ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);

        // set up 100 "random" messages we use a seeded random here to make reload testing easier.
        SecureRandom pointRandom = new SecureRandom()
        {
            int counter = 1;

            public void nextBytes(byte[] data)
            {
                data[0] = (byte)counter++;
            }
        };

        final int numMessages = 100;

        final Set<ECPoint> part1 = new HashSet<>();
        final Set<ECPoint> part2 = new HashSet<>();

        final ECPoint[] plainText1 = new ECPoint[numMessages];
        final ECPoint[] plainText2 = new ECPoint[numMessages];
        for (int i = 0; i != plainText1.length; i++)
        {
            plainText1[i] = generatePoint(pubKey.getParameters(), pointRandom);
            plainText2[i] = generatePoint(pubKey.getParameters(), pointRandom);

            part1.add(plainText1[i]);
            part2.add(plainText2[i]);

            PairSequence encrypted = new PairSequence(new ECPair[] { encryptor.encrypt(plainText1[i]), encryptor.encrypt(plainText2[i]) });           // two column ballot

            client.uploadMessage("FRED", encrypted.getEncoded());
        }

        CommandService commandService = adminRegistrar.connect(CommandService.class);

        // board is hosted on "B" move to "A" then to "C" then back to "B"
        Operation<ShuffleOperationListener> shuffleOp = commandService.doShuffleAndMove("FRED",  new ShuffleOptions.Builder(MultiColumnRowTransform.NAME).setKeyID("ECENCKEY").build(), "A", "C", "C");

        final CountDownLatch shuffleLatch = new CountDownLatch(1);

        shuffleOp.addListener(new ShuffleOperationListener()
        {
            @Override
            public void completed()
            {
                shuffleLatch.countDown();
                System.err.println("done");
            }

            @Override
            public void status(String statusObject)
            {
                System.err.println("status: " + statusObject);
            }

            @Override
            public void failed(String errorObject)
            {
                shuffleLatch.countDown();
                System.err.println("failed: " + errorObject);
            }
        });

        shuffleLatch.await();

        final CountDownLatch downloadLatch = new CountDownLatch(1);

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents("FRED", new DownloadOptions.Builder().withKeyID("ECENCKEY").withThreshold(2).withNodes("A", "B").build(), new DownloadOperationListener()
        {
            int counter = 0;

            @Override
            public void messageDownloaded(int index, byte[] message)
            {
                PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);

                if (part1.remove(decrypted.getECPoints()[0]) && part2.remove(decrypted.getECPoints()[1]))
                {
                    System.err.println(index + " message downloaded successfully");
                }
                else
                {
                    System.err.println(index + " decryption failed");
                }
                counter++;
            }

            @Override
            public void completed()
            {
                downloadLatch.countDown();
                System.err.println("completed " + (numMessages == counter));
            }

            @Override
            public void status(String statusObject)
            {
                System.err.println("status: " + statusObject);
            }

            @Override
            public void failed(String errorObject)
            {
                downloadLatch.countDown();
                System.err.println("failed");
            }
        });

        downloadLatch.await();

        keyGenerationService.shutdown();
        commandService.shutdown();
    }
}
