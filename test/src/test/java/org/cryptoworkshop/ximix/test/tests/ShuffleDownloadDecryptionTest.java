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
package org.cryptoworkshop.ximix.test.tests;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import junit.framework.TestCase;
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
import org.cryptoworkshop.ximix.client.DownloadOperationListener;
import org.cryptoworkshop.ximix.client.DownloadShuffleResultOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.ShuffleOperationListener;
import org.cryptoworkshop.ximix.client.ShuffleOptions;
import org.cryptoworkshop.ximix.client.ShuffleStatus;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptsDownloadOperationListener;
import org.cryptoworkshop.ximix.client.UploadService;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.client.verify.ECShuffledTranscriptVerifier;
import org.cryptoworkshop.ximix.client.verify.LinkIndexVerifier;
import org.cryptoworkshop.ximix.client.verify.SignedDataVerifier;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.asn1.message.SeedAndWitnessMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.Operation;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.mixnet.transform.MultiColumnRowTransform;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.cryptoworkshop.ximix.test.node.SquelchingThrowableHandler;
import org.cryptoworkshop.ximix.test.node.TestNotifier;
import org.junit.Assert;
import org.junit.Test;

import static org.cryptoworkshop.ximix.test.node.NodeTestUtil.getXimixNode;

/**
 *
 */
public class ShuffleDownloadDecryptionTest
    extends TestCase
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

    @Override
    public void tearDown()
        throws Exception
    {
        //
        // Shutdown any registered nodes.
        //
        //NodeTestUtil.shutdownNodes();
    }

    @Override
    public void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testShuffleVerification()
        throws Exception
    {
        doShuffleDownloadTest(20);
    }

    @Test
    public void testSingleBallotShuffleVerification()
        throws Exception
    {
        doShuffleDownloadTest(1);
    }

    private void doShuffleDownloadTest(int numberOfPoints)
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();
        handler.squelchType(SocketException.class);

        PEMParser pemParser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("/conf/trustCa.pem")));
        X509Certificate trustAnchor;

        try
        {
            trustAnchor = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder)pemParser.readObject());
        }
        catch (Exception e)
        {
            throw new IllegalStateException("Can't parse trust anchor.", e);
        }

        //
        // Set up nodes.
        //
        File tmpDir = File.createTempFile("xmx", ".wrk");
        tmpDir.delete();

        tmpDir.mkdir();

        XimixNode nodeOne = getXimixNode(new File(tmpDir, "node1"), "/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode(new File(tmpDir, "node2"), "/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode(new File(tmpDir, "node3"), "/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree);

        XimixNode nodeFour = getXimixNode(new File(tmpDir, "node4"), "/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour);

        XimixNode nodeFive = getXimixNode(new File(tmpDir, "node5"), "/conf/mixnet.xml", "/conf/node5.xml", handler);
        NodeTestUtil.launch(nodeFive);

        SecureRandom random = new SecureRandom();

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"), new TestNotifier());

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.EC_ELGAMAL, "secp256r1")
            .withThreshold(4)
            .withNodes("A", "B", "C", "D", "E")
            .build();

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

        CommandService commandService = adminRegistrar.connect(CommandService.class);

        commandService.createBoard("FRED", new BoardCreationOptions.Builder("B").build());

        UploadService client = adminRegistrar.connect(UploadService.class);

        final ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        final ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);


        //
        // Set up plain text and upload encrypted pair.
        //
        final ECPoint[] plainText1 = new ECPoint[numberOfPoints];
        final ECPoint[] plainText2 = new ECPoint[numberOfPoints];
        final Set<ECPoint> plain1 = new HashSet<>();
        final Set<ECPoint> plain2 = new HashSet<>();

        //
        // Encrypt and submit.
        //
        for (int i = 0; i < plainText1.length; i++)
        {
            plainText1[i] = generatePoint(pubKey.getParameters(), random);
            plainText2[i] = generatePoint(pubKey.getParameters(), random);

            plain1.add(plainText1[i]);
            plain2.add(plainText2[i]);

            PairSequence encrypted = new PairSequence(new ECPair[]{encryptor.encrypt(plainText1[i]), encryptor.encrypt(plainText2[i])});

            client.uploadMessage("FRED", encrypted.getEncoded());
        }

        //
        // Perform shuffle.
        //
        final CountDownLatch shufflerLatch = new CountDownLatch(1);

        final AtomicBoolean shuffleCompleted = new AtomicBoolean(false);
        final AtomicBoolean shuffleFailed = new AtomicBoolean(false);
        final AtomicReference<Thread> shuffleThread = new AtomicReference<>();
        final Map<String, byte[]> seedCommitmentMap = new HashMap<>();

        ShuffleOperationListener shuffleListener = new ShuffleOperationListener()
        {
            @Override
            public void commit(Map<String, byte[]> seedCommitments)
            {
                seedCommitmentMap.putAll(seedCommitments);
            }

            @Override
            public void completed()
            {
                shuffleCompleted.set(true);
                TestUtil.checkThread(shuffleThread);
                shufflerLatch.countDown();
            }

            @Override
            public void status(ShuffleStatus statusObject)
            {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void failed(ShuffleStatus errorObject)
            {
                shuffleFailed.set(true);
                shufflerLatch.countDown();
                TestUtil.checkThread(shuffleThread);
            }
        };

        Operation<ShuffleOperationListener> shuffleOp = commandService.doShuffleAndMove("FRED",
            new ShuffleOptions.Builder(MultiColumnRowTransform.NAME).withKeyID("ECKEY").build(), shuffleListener, "A", "C", "D");


        shufflerLatch.await();

        //
        // Fail if operation did not complete in the nominated time frame.
        //
        //TestCase.assertTrue("Shuffle timed out.", shufflerLatch.await(20, TimeUnit.SECONDS));


        //
        // Check that failed and completed methods are exclusive.
        //

        TestCase.assertNotSame("Failed flag and completed flag must be different.", shuffleCompleted.get(), shuffleFailed.get());

        //
        // Check for success of shuffle.
        //
        TestCase.assertTrue(shuffleCompleted.get());

        //
        // Check that shuffle did not fail.
        //
        TestCase.assertFalse(shuffleFailed.get());


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

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(), new ShuffleTranscriptOptions.Builder(TranscriptType.GENERAL).build(), transcriptListener, "A", "C", "D");

        transcriptCompleted.await();

        LinkIndexVerifier.Builder builder = new LinkIndexVerifier.Builder(numberOfPoints);

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
                fail("General commitment check signature failed");
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
                fail("General commitment check signature failed");
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

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(), new ShuffleTranscriptOptions.Builder(TranscriptType.WITNESSES).withChallengeSeed(challengeSeed).build(), transcriptListener, "A", "C", "D");

        witnessTranscriptCompleted.await();

        for (Integer step : witnessTranscripts.keySet())
        {
            byte[] bytes = witnessTranscripts.get(step);

            if (!signatureVerifier.signatureVerified(new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), bytes)))
            {
                fail("Witness commitment check signature failed");
            }
        }

        //
        // verify the witness transcripts are correctly generated
        //
        for (Integer step : witnessTranscripts.keySet())
        {
            byte[] bytes = witnessTranscripts.get(step);

            linkVerifier.verify(step, false, new ByteArrayInputStream(bytes));
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
            .withKeyID("ECKEY")
            .withThreshold(4)
            .withPairingEnabled(true)
            .withNodes("A", "B", "C", "D").build(), streamSeedCommitments, streamSeedsAndWitnesses, streamGeneralTranscripts, streamWitnessTranscripts, new DownloadOperationListener()
        {
            @Override
            public void messageDownloaded(int index, byte[] message, List<byte[]> proofs)
            {
                PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);

                Assert.assertTrue(plain1.remove(decrypted.getECPoints()[0]) && plain2.remove(decrypted.getECPoints()[1]));
            }

            @Override
            public void completed()
            {
                shuffleOutputDownloadCompleted.countDown();
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

        TestCase.assertTrue(plain1.isEmpty());
        TestCase.assertTrue(plain2.isEmpty());

        NodeTestUtil.shutdownNodes();
        client.shutdown();
        commandService.shutdown();

        delete(tmpDir);
    }

    @Test
    public void testShuffleVerificationWithPairing()
        throws Exception
    {
        doTestWithPairingFlag(20, true);
    }

    @Test
    public void testShuffleVerificationWithoutPairingWithDuplicate()
        throws Exception
    {
        doTestWithPairingFlag(20, false);
    }

    @Test
    public void testSingleBallotShuffleVerificationWithPairing()
        throws Exception
    {
        doTestWithPairingFlag(1, true);
    }

    @Test
    public void testTwoBallotShuffleVerificationWithPairing()
        throws Exception
    {
        doTestWithPairingFlag(2, true);
    }

    @Test
    public void testThreeBallotShuffleVerificationWithPairing()
        throws Exception
    {
        doTestWithPairingFlag(3, true);
    }

    @Test
    public void testSingleBallotShuffleVerificationWithoutPairingWithDuplicate()
        throws Exception
    {
        doTestWithPairingFlag(1, false);
    }

    private void doTestWithPairingFlag(int numberOfPoints, boolean isPairingEnabled)
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();
        handler.squelchType(SocketException.class);

        PEMParser pemParser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("/conf/trustCa.pem")));
        X509Certificate trustAnchor;

        try
        {
            trustAnchor = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder)pemParser.readObject());
        }
        catch (Exception e)
        {
            throw new IllegalStateException("Can't parse trust anchor.", e);
        }

        //
        // Set up nodes.
        //
        File tmpDir = File.createTempFile("xmx", ".wrk");
        tmpDir.delete();

        tmpDir.mkdir();

        XimixNode nodeOne = getXimixNode(new File(tmpDir, "node1"), "/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode(new File(tmpDir, "node2"), "/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode(new File(tmpDir, "node3"), "/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree);

        XimixNode nodeFour = getXimixNode(new File(tmpDir, "node4"), "/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour);

        XimixNode nodeFive = getXimixNode(new File(tmpDir, "node5"), "/conf/mixnet.xml", "/conf/node5.xml", handler);
        NodeTestUtil.launch(nodeFive);


        SecureRandom random = new SecureRandom();

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"), new TestNotifier());

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.EC_ELGAMAL, "secp256r1")
            .withThreshold(4)
            .withNodes("A", "B", "C", "D", "E")
            .build();

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

        CommandService commandService = adminRegistrar.connect(CommandService.class);

        commandService.createBoard("FRED", new BoardCreationOptions.Builder("B").build());

        UploadService client = adminRegistrar.connect(UploadService.class);

        final ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        final ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);


        //
        // Set up plain text and upload encrypted pair.
        //
        final ECPoint[] plainText1 = new ECPoint[numberOfPoints];
        final ECPoint[] plainText2 = new ECPoint[numberOfPoints];
        final Set<ECPoint> plain1 = new HashSet<>();
        final Set<ECPoint> plain2 = new HashSet<>();

        //
        // Encrypt and submit.
        //
        for (int i = 0; i < plainText1.length; i++)
        {
            plainText1[i] = generatePoint(pubKey.getParameters(), random);
            plainText2[i] = generatePoint(pubKey.getParameters(), random);

            plain1.add(plainText1[i]);
            plain2.add(plainText2[i]);

            PairSequence encrypted = new PairSequence(new ECPair[]{encryptor.encrypt(plainText1[i]), encryptor.encrypt(plainText2[i])});

            client.uploadMessage("FRED", encrypted.getEncoded());
        }

        //
        // Perform shuffle.
        //
        final CountDownLatch shufflerLatch = new CountDownLatch(1);

        final AtomicBoolean shuffleCompleted = new AtomicBoolean(false);
        final AtomicBoolean shuffleFailed = new AtomicBoolean(false);
        final AtomicReference<Thread> shuffleThread = new AtomicReference<>();
        final Map<String, byte[]> seedCommitmentMap = new HashMap<>();

        ShuffleOperationListener shuffleListener = new ShuffleOperationListener()
        {
            @Override
            public void commit(Map<String, byte[]> seedCommitments)
            {
                seedCommitmentMap.putAll(seedCommitments);
            }

            @Override
            public void completed()
            {
                shuffleCompleted.set(true);
                TestUtil.checkThread(shuffleThread);
                shufflerLatch.countDown();
            }

            @Override
            public void status(ShuffleStatus statusObject)
            {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void failed(ShuffleStatus errorObject)
            {
                shuffleFailed.set(true);
                shufflerLatch.countDown();
                TestUtil.checkThread(shuffleThread);
            }
        };

        Operation<ShuffleOperationListener> shuffleOp = commandService.doShuffleAndMove("FRED",
            new ShuffleOptions.Builder(MultiColumnRowTransform.NAME).withKeyID("ECKEY").build(), shuffleListener, "A", "A", "C", "D");


        shufflerLatch.await();

        //
        // Fail if operation did not complete in the nominated time frame.
        //
        //TestCase.assertTrue("Shuffle timed out.", shufflerLatch.await(20, TimeUnit.SECONDS));


        //
        // Check that failed and completed methods are exclusive.
        //

        TestCase.assertNotSame("Failed flag and completed flag must be different.", shuffleCompleted.get(), shuffleFailed.get());

        //
        // Check for success of shuffle.
        //
        TestCase.assertTrue(shuffleCompleted.get());

        //
        // Check that shuffle did not fail.
        //
        TestCase.assertFalse(shuffleFailed.get());


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

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(), new ShuffleTranscriptOptions.Builder(TranscriptType.GENERAL).withPairingEnabled(isPairingEnabled).build(), transcriptListener, "A", "C", "D");

        transcriptCompleted.await();

        LinkIndexVerifier.Builder builder = new LinkIndexVerifier.Builder(numberOfPoints);

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
                fail("General commitment check signature failed");
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
                fail("General commitment check signature failed");
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

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(), new ShuffleTranscriptOptions.Builder(TranscriptType.WITNESSES).withChallengeSeed(challengeSeed).withPairingEnabled(isPairingEnabled).build(), transcriptListener, "A", "C", "D");

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

            linkVerifier.verify(step, isPairingEnabled, new ByteArrayInputStream(bytes));
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
            .withKeyID("ECKEY")
            .withThreshold(4)
            .withPairingEnabled(isPairingEnabled)
            .withNodes("A", "B", "C", "D").build(), streamSeedCommitments, streamSeedsAndWitnesses, streamGeneralTranscripts, streamWitnessTranscripts, new DownloadOperationListener()
        {
            @Override
            public void messageDownloaded(int index, byte[] message, List<byte[]> proofs)
            {
                PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);

                Assert.assertTrue(plain1.remove(decrypted.getECPoints()[0]) && plain2.remove(decrypted.getECPoints()[1]));
            }

            @Override
            public void completed()
            {
                shuffleOutputDownloadCompleted.countDown();
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

        TestCase.assertTrue(plain1.isEmpty());
        TestCase.assertTrue(plain2.isEmpty());

        NodeTestUtil.shutdownNodes();
        client.shutdown();
        commandService.shutdown();

        delete(tmpDir);
    }

    public static void delete(File file)
        throws IOException
    {

        if (file.isDirectory())
        {
            for (File temp : file.listFiles())
            {
                delete(temp);
            }

            file.delete();
        }
        else
        {
            file.delete();
        }
    }
}
