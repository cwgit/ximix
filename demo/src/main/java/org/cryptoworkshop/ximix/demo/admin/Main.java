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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cryptoworkshop.ximix.client.BoardCreationOptions;
import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.DecryptionChallengeSpec;
import org.cryptoworkshop.ximix.client.DownloadOperationListener;
import org.cryptoworkshop.ximix.client.DownloadOptions;
import org.cryptoworkshop.ximix.client.DownloadShuffleResultOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.MessageChooser;
import org.cryptoworkshop.ximix.client.ShuffleOperationListener;
import org.cryptoworkshop.ximix.client.ShuffleOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptsDownloadOperationListener;
import org.cryptoworkshop.ximix.client.UploadService;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.client.verify.ECDecryptionChallengeVerifier;
import org.cryptoworkshop.ximix.client.verify.ECShuffledTranscriptVerifier;
import org.cryptoworkshop.ximix.client.verify.LinkIndexVerifier;
import org.cryptoworkshop.ximix.client.verify.SignedDataVerifier;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.asn1.message.SeedAndWitnessMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.Operation;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.node.mixnet.transform.MultiColumnRowTransform;

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
        Security.addProvider(new BouncyCastleProvider());

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(new File(args[0]), new EventNotifier()
        {
            @Override
            public void notify(Level level, Throwable throwable)
            {
                System.err.print(level + " " + throwable.getMessage());
                throwable.printStackTrace(System.err);
            }

            @Override
            public void notify(Level level, Object detail)
            {
                System.err.println(level + " " + detail.toString());
            }

            @Override
            public void notify(Level level, Object detail, Throwable throwable)
            {
                System.err.println(level + " " + detail.toString());
                throwable.printStackTrace(System.err);
            }
        });

        PEMParser pParse = new PEMParser(new FileReader(args[1]));

        X509Certificate trustAnchor = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder)pParse.readObject());

        pParse.close();

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        byte[] encPubKey = keyGenerationService.fetchPublicKey("ECENCKEY");

        if (encPubKey == null)
        {
            KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.EC_ELGAMAL, "secp256r1")
                .withThreshold(4)
                .withNodes("A", "B", "C", "D", "E")
                .build();

            encPubKey = keyGenerationService.generatePublicKey("ECENCKEY", keyGenOptions);
        }

        byte[] sigPubKey = keyGenerationService.fetchPublicKey("ECSIGKEY");

        if (sigPubKey == null)
        {
            KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.ECDSA, "secp256r1")
                                                       .withThreshold(2)
                                                       .withNodes("A", "B", "C", "D", "E")
                                                       .build();


            sigPubKey = keyGenerationService.generatePublicKey("ECSIGKEY", keyGenOptions);
        }

        byte[] blsPubKey = keyGenerationService.fetchPublicKey("BLSSIGKEY");

        if (blsPubKey == null)
        {
            KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.BLS, "d62003-159-158.param")
                                                       .withThreshold(3)
                                                       .withNodes("A", "B", "C", "D", "E")
                                                       .build();


            blsPubKey = keyGenerationService.generatePublicKey("BLSSIGKEY", keyGenOptions);
        }

        CommandService commandService = adminRegistrar.connect(CommandService.class);

        if (!commandService.isBoardExisting("FRED"))
        {
            commandService.createBoard("FRED", new BoardCreationOptions.Builder("B").withBackUpHost("A").build());
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

        final Set<ECPoint> verifiedPart1 = new HashSet<>(part1);
        final Set<ECPoint> verifiedPart2 = new HashSet<>(part2);

        // board is hosted on "B" move to "A" then to "C" then back to "B"

        final CountDownLatch shuffleLatch = new CountDownLatch(1);
        final Map<String, byte[]> seedCommitmentMap = new HashMap<>();

        ShuffleOperationListener shuffleListener = new ShuffleOperationListener()
        {
            @Override
            public void commit(Map<String, byte[]> seedCommitments)
            {
                seedCommitmentMap.putAll(seedCommitments);
            }

            @Override
            public void status(String statusObject)
            {
                System.err.println("status: " + statusObject);
            }

            @Override
            public void completed()
            {
                shuffleLatch.countDown();
                System.err.println("done");
            }

            @Override
            public void failed(String errorObject)
            {
                shuffleLatch.countDown();
                System.err.println("failed: " + errorObject);
            }
        };

        Operation<ShuffleOperationListener> shuffleOp = commandService.doShuffleAndMove("FRED",  new ShuffleOptions.Builder(MultiColumnRowTransform.NAME).withKeyID("ECENCKEY").build(), shuffleListener, "A", "A", "C", "C", "D");

        shuffleLatch.await();

        final CountDownLatch downloadLatch = new CountDownLatch(1);

        ByteArrayOutputStream challengeLogStream = new ByteArrayOutputStream();

        DecryptionChallengeSpec decryptionChallengeSpec = new DecryptionChallengeSpec(new MessageChooser()
        {
            @Override
            public boolean chooseMessage(int index)
            {
                return index % 5 == 0;
            }
        },
        challengeLogStream);

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents("FRED",
                                                                                       new DownloadOptions.Builder()
                                                                                              .withKeyID("ECENCKEY")
                                                                                              .withThreshold(4)
                                                                                              .withNodes("A", "B", "C", "D")
                                                                                              .withChallengeSpec(decryptionChallengeSpec).build(), new DownloadOperationListener()
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

        //
        // verify the decryption challenge log.
        //
        ECDecryptionChallengeVerifier challengeVerifier = new ECDecryptionChallengeVerifier(pubKey, new ByteArrayInputStream(challengeLogStream.toByteArray()));

        challengeVerifier.verify();

        Map<String, byte[][]> seedAndWitnessesMap = commandService.downloadShuffleSeedsAndWitnesses("FRED", shuffleOp.getOperationNumber(), "A", "C", "D");


        SignedDataVerifier signatureVerifier = new SignedDataVerifier(trustAnchor);

        final CountDownLatch transcriptCompleted = new CountDownLatch(1);

        final Map<Integer, byte[]> generalTranscripts = new TreeMap<>();

        ShuffleTranscriptsDownloadOperationListener transcriptListener = new ShuffleTranscriptsDownloadOperationListener()
        {
            @Override
            public void shuffleTranscriptArrived(long operationNumber, int stepNumber, InputStream transcript)
            {
                try
                {
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    BufferedInputStream bIn = new BufferedInputStream(transcript);

                    int ch;
                    while ((ch = bIn.read()) >= 0)
                    {
                        bOut.write(ch);
                    }
                    bOut.close();

                    generalTranscripts.put(stepNumber, bOut.toByteArray());
                }
                catch (IOException e)
                {
                    e.printStackTrace();
                }
            }

            @Override
            public void completed()
            {
                transcriptCompleted.countDown();
            }

            @Override
            public void status(String statusObject)
            {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void failed(String errorObject)
            {
                System.err.println("failed: " + errorObject);
                transcriptCompleted.countDown();
            }
        };

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(),  new ShuffleTranscriptOptions.Builder(TranscriptType.GENERAL).build(), transcriptListener, "A", "C", "D");

        transcriptCompleted.await();

        LinkIndexVerifier.Builder builder = new LinkIndexVerifier.Builder(numMessages);

        builder.setNetworkSeeds(seedCommitmentMap, seedAndWitnessesMap);

        for (Integer step : generalTranscripts.keySet())
        {
            byte[] bytes = generalTranscripts.get(step);

            if (signatureVerifier.signatureVerified(new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), bytes)))
            {
                 builder.addTranscript(new ByteArrayInputStream(bytes));
            }
            else
            {
                System.err.println("General commitment check signature failed");
            }
        }

        LinkIndexVerifier linkVerifier = builder.build();

        byte[] challengeSeed = linkVerifier.getChallengeSeed();

        System.err.println("network seed: " + new String(Hex.encode(challengeSeed)));

        for (Integer step : generalTranscripts.keySet())
        {
            byte[] bytes = generalTranscripts.get(step);

            if (!signatureVerifier.signatureVerified(new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), bytes)))
            {
                System.err.println("General commitment check signature failed");
            }
        }

        //
        // added the distributed seed
        //
        final Map<Integer, byte[]> witnessTranscripts = new TreeMap<>();

        final CountDownLatch witnessTranscriptCompleted = new CountDownLatch(1);
        transcriptListener = new ShuffleTranscriptsDownloadOperationListener()
        {
            @Override
            public void shuffleTranscriptArrived(long operationNumber, int stepNumber, InputStream transcript)
            {
                try
                {
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    BufferedInputStream bIn = new BufferedInputStream(transcript);

                    int ch;
                    while ((ch = bIn.read()) >= 0)
                    {
                        bOut.write(ch);
                    }
                    bOut.close();

                    witnessTranscripts.put(stepNumber, bOut.toByteArray());
                }
                catch (IOException e)
                {
                    e.printStackTrace();
                }
            }

            @Override
            public void completed()
            {
                witnessTranscriptCompleted.countDown();
            }

            @Override
            public void status(String statusObject)
            {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void failed(String errorObject)
            {
                witnessTranscriptCompleted.countDown();
            }
        };

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(),  new ShuffleTranscriptOptions.Builder(TranscriptType.WITNESSES).withChallengeSeed(challengeSeed).withPairingEnabled(true).build(), transcriptListener, "A", "C", "D");

        witnessTranscriptCompleted.await();

        for (Integer step : witnessTranscripts.keySet())
        {
            byte[] bytes = witnessTranscripts.get(step);

            if (!signatureVerifier.signatureVerified(new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), bytes)))
            {
                System.err.println("Witness commitment check signature failed");
            }
        }

        //
        // verify the witness transcripts are correctly generated
        //
        for (Integer step : witnessTranscripts.keySet())
        {
            byte[] bytes = witnessTranscripts.get(step);

            linkVerifier.verify(step, true, new ByteArrayInputStream(bytes));
        }

        //
        // verify the revealed commitments.
        //
        for (Integer key : witnessTranscripts.keySet())
        {
            byte[] transcript = witnessTranscripts.get(key);
            byte[] initialTranscript = generalTranscripts.get(key);
            byte[] nextTranscript = generalTranscripts.get(key + 1);

            ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, new ByteArrayInputStream(transcript), new ByteArrayInputStream(initialTranscript), new ByteArrayInputStream(nextTranscript));

            verifier.verify();
        }

        System.err.println("transcripts verified");

        Map<String, InputStream> streamSeedCommitments = new HashMap<>();
        for (String key : seedCommitmentMap.keySet())
        {
            streamSeedCommitments.put(key, new ByteArrayInputStream(seedCommitmentMap.get(key)));
        }

        Map<String, InputStream> streamSeedsAndWitnesses = new HashMap<>();
        for (String key : seedAndWitnessesMap.keySet())
        {
            byte[][] sAndW = seedAndWitnessesMap.get(key);
            streamSeedsAndWitnesses.put(key, new ByteArrayInputStream(new SeedAndWitnessMessage(sAndW[0], sAndW[1]).getEncoded()));
        }

        Map<Integer, InputStream> streamWitnessTranscripts = new HashMap<>();
        for (Integer key : witnessTranscripts.keySet())
        {
            streamWitnessTranscripts.put(key, new ByteArrayInputStream(witnessTranscripts.get(key)));
        }

        Map<Integer, InputStream> streamGeneralTranscripts = new HashMap<>();
        for (Integer key : generalTranscripts.keySet())
        {
            streamGeneralTranscripts.put(key, new ByteArrayInputStream(generalTranscripts.get(key)));
        }

        final CountDownLatch shuffleOutputDownloadCompleted = new CountDownLatch(1);

        commandService.downloadShuffleResult("FRED", new DownloadShuffleResultOptions.Builder()
                                                                      .withKeyID("ECENCKEY")
                                                                      .withThreshold(4)
                                                                      .withPairingEnabled(true)
                                                                      .withNodes("A", "B", "C", "D").build(), streamSeedCommitments, streamSeedsAndWitnesses, streamGeneralTranscripts, streamWitnessTranscripts, new DownloadOperationListener()
        {
            int counter = 0;

            @Override
            public void messageDownloaded(int index, byte[] message)
            {
                PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);

                if (verifiedPart1.remove(decrypted.getECPoints()[0]) && verifiedPart2.remove(decrypted.getECPoints()[1]))
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
                shuffleOutputDownloadCompleted.countDown();
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
                shuffleOutputDownloadCompleted.countDown();
                System.err.println("failed " + errorObject);
            }
        });

        shuffleOutputDownloadCompleted.await();

        keyGenerationService.shutdown();
        commandService.shutdown();
    }
}
