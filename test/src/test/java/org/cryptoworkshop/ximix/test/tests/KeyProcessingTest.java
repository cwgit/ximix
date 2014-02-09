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
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import junit.framework.TestCase;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.BoardCreationOptions;
import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.DownloadOperationListener;
import org.cryptoworkshop.ximix.client.DownloadOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.ShuffleOperationListener;
import org.cryptoworkshop.ximix.client.ShuffleOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptsDownloadOperationListener;
import org.cryptoworkshop.ximix.client.UploadService;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.client.verify.ECDecryptionChallengeVerifier;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.Operation;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.mixnet.transform.MultiColumnRowTransform;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.cryptoworkshop.ximix.test.node.SquelchingThrowableHandler;
import org.cryptoworkshop.ximix.test.node.TestNotifier;
import org.cryptoworkshop.ximix.test.node.ValueObject;
import org.junit.Test;

import static org.cryptoworkshop.ximix.test.node.NodeTestUtil.getXimixNode;

/**
 *
 */
public class KeyProcessingTest extends TestCase
{
    static
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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

    }

    @Test
    public void testWithNodesMixedMissingFromGeneration()
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();
        handler.squelchType(SocketException.class);

        //
        // Set up nodes.
        //

        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml", handler);
        NodeTestUtil.launch(nodeFive);

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"), new TestNotifier());

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.EC_ELGAMAL, "secp256r1")
            .withThreshold(3)
            .withNodes("A", "B", "C", "D", "E" )
            .build();

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

        UploadService client = adminRegistrar.connect(UploadService.class);
        CommandService commandService = adminRegistrar.connect(CommandService.class);

        commandService.createBoard("FRED", new BoardCreationOptions.Builder("B").build());

        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        doMixedMissingTest(client, commandService, pubKey, new String[] { "A", "B", "C" });
        doMixedMissingTest(client, commandService, pubKey, new String[] { "C", "D", "E" });
        doMixedMissingTest(client, commandService, pubKey, new String[] { "A", "D", "E" });
        doMixedMissingTest(client, commandService, pubKey, new String[] { "A", "D", "B" });

        NodeTestUtil.shutdownNodes();
        client.shutdown();
        commandService.shutdown();
    }

    private void doMixedMissingTest(UploadService client, CommandService commandService, final ECPublicKeyParameters pubKey, String[] decNodes)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);

        //
        // Set up plain text and upload encrypted pair.
        //

        int numberOfPoints = 15; // Adjust number of points to test here.


        final ECPoint[] plainText1 = new ECPoint[numberOfPoints];
        final ECPoint[] plainText2 = new ECPoint[numberOfPoints];


        //
        // Encrypt and submit.
        //
        for (int i = 0; i < plainText1.length; i++)
        {
            plainText1[i] = generatePoint(pubKey.getParameters(), random);
            plainText2[i] = generatePoint(pubKey.getParameters(), random);

            PairSequence encrypted = new PairSequence(new ECPair[]{encryptor.encrypt(plainText1[i]), encryptor.encrypt(plainText2[i])});

            client.uploadMessage("FRED", encrypted.getEncoded());
        }


        final ECPoint[] resultText1 = new ECPoint[plainText1.length];
        final ECPoint[] resultText2 = new ECPoint[plainText2.length];
        final AtomicBoolean downloadBoardCompleted = new AtomicBoolean(false);
        final AtomicBoolean downloadBoardFailed = new AtomicBoolean(false);
        final CountDownLatch encryptLatch = new CountDownLatch(1);
        final AtomicReference<Thread> decryptThread = new AtomicReference<>();

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents(
            "FRED",
            new DownloadOptions.Builder()
                .withKeyID("ECKEY")
                .withThreshold(3)
                .withNodes(decNodes).build(),
            new DownloadOperationListener()
            {
                int counter = 0;

                @Override
                public void messageDownloaded(int index, byte[] message, List<byte[]> proofs)
                {
                    PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);
                    resultText1[counter] = decrypted.getECPoints()[0];
                    resultText2[counter++] = decrypted.getECPoints()[1];
                    TestUtil.checkThread(decryptThread);
                }

                @Override
                public void completed()
                {
                    downloadBoardCompleted.set(true);
                    TestUtil.checkThread(decryptThread);
                    encryptLatch.countDown();
                }

                @Override
                public void status(String statusObject)
                {
                    TestUtil.checkThread(decryptThread);
                }

                @Override
                public void failed(String errorObject)
                {
                    TestUtil.checkThread(decryptThread);
                    downloadBoardFailed.set(true);
                    encryptLatch.countDown();
                }
            });


        TestCase.assertTrue(encryptLatch.await(20, TimeUnit.SECONDS));

        TestCase.assertNotSame("Failed and complete must be different.", downloadBoardFailed.get(), downloadBoardCompleted.get());
        TestCase.assertTrue("Complete method called in DownloadOperationListener", downloadBoardCompleted.get());
        TestCase.assertFalse("Not failed.", downloadBoardFailed.get());

      //  TestCase.assertEquals("Shuffle and decrypt threads different.", decryptThread.get(), shuffleThread.get());


        //
        // Validate result points against plainText points.
        //

        for (int t = 0; t < plainText1.length; t++)
        {
            TestCase.assertTrue(plainText1[t].equals(resultText1[t]));
            TestCase.assertTrue(plainText2[t].equals(resultText2[t]));
        }
    }

    @Test
    public void testKeyGenerationEncryptionTestWithShuffle()
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();
        handler.squelchType(SocketException.class);

        //
        // Set up nodes.
        //

        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml", handler);
        NodeTestUtil.launch(nodeFive);


        SecureRandom random = new SecureRandom();

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"), new TestNotifier());

        CommandService commandService = adminRegistrar.connect(CommandService.class);

        commandService.createBoard("FRED", new BoardCreationOptions.Builder("B").build());

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.EC_ELGAMAL, "secp256r1")
            .withThreshold(4)
            .withNodes("A", "B", "C", "D", "E")
            .build();

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

        UploadService client = adminRegistrar.connect(UploadService.class);

        final ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        final ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);


        //
        // Set up plain text and upload encrypted pair.
        //

        int numberOfPoints = 20; // Adjust number of points to test here.


        final ECPoint[] plainText1 = new ECPoint[numberOfPoints];
        final ECPoint[] plainText2 = new ECPoint[numberOfPoints];
        Set<ECPoint> plain1 = new HashSet<>();
        Set<ECPoint> plain2 = new HashSet<>();

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

        ShuffleOperationListener shuffleListener = new ShuffleOperationListener()
        {
            @Override
            public void commit(Map<String, byte[]> seedCommitments)
            {

            }

            @Override
            public void completed()
            {
                shuffleCompleted.set(true);
                TestUtil.checkThread(shuffleThread);
                shufflerLatch.countDown();
            }

            @Override
            public void status(String statusObject)
            {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void failed(String errorObject)
            {
                shuffleFailed.set(true);
                shufflerLatch.countDown();
                TestUtil.checkThread(shuffleThread);
            }
        };

        Operation<ShuffleOperationListener> shuffleOp = commandService.doShuffleAndMove("FRED",
            new ShuffleOptions.Builder(MultiColumnRowTransform.NAME).withKeyID("ECKEY").build(), shuffleListener, "A", "C", "D", "E");


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

        final CountDownLatch transcriptCompleted = new CountDownLatch(1);

        final Map<String, byte[]> generalTranscripts = new HashMap<>();

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

                    generalTranscripts.put(Long.toHexString(operationNumber) + "." + stepNumber, bOut.toByteArray());
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
               transcriptCompleted.countDown();
            }
        };

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(),  new ShuffleTranscriptOptions.Builder(TranscriptType.GENERAL).build(), transcriptListener,  "A", "C", "D", "E");

        transcriptCompleted.await();

        TestCase.assertEquals(5, generalTranscripts.size());

        final Map<String, byte[]> witnessTranscripts = new HashMap<>();

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

                    witnessTranscripts.put(Long.toHexString(operationNumber) + "." + stepNumber, bOut.toByteArray());
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

        commandService.downloadShuffleTranscripts("FRED", shuffleOp.getOperationNumber(),  new ShuffleTranscriptOptions.Builder(TranscriptType.WITNESSES).withChallengeSeed(new byte[55]).build(), transcriptListener,  "A", "C", "D", "E");

        witnessTranscriptCompleted.await();

        TestCase.assertEquals(4, witnessTranscripts.size());

        final ECPoint[] resultText1 = new ECPoint[plainText1.length];
        final ECPoint[] resultText2 = new ECPoint[plainText2.length];
        final AtomicBoolean downloadBoardCompleted = new AtomicBoolean(false);
        final AtomicBoolean downloadBoardFailed = new AtomicBoolean(false);
        final CountDownLatch encryptLatch = new CountDownLatch(1);
        final AtomicReference<Thread> decryptThread = new AtomicReference<>();

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents(
            "FRED",
            new DownloadOptions.Builder()
                .withKeyID("ECKEY")
                .withThreshold(4)
                .withNodes("A", "B", "C", "D", "E").build(),
            new DownloadOperationListener()
            {
                int counter = 0;

                @Override
                public void messageDownloaded(int index, byte[] message, List<byte[]> proofs)
                {
                    PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);
                    resultText1[counter] = decrypted.getECPoints()[0];
                    resultText2[counter++] = decrypted.getECPoints()[1];
                    TestUtil.checkThread(decryptThread);
                }

                @Override
                public void completed()
                {
                    downloadBoardCompleted.set(true);
                    TestUtil.checkThread(decryptThread);
                    encryptLatch.countDown();
                }

                @Override
                public void status(String statusObject)
                {
                    TestUtil.checkThread(decryptThread);
                }

                @Override
                public void failed(String errorObject)
                {
                    TestUtil.checkThread(decryptThread);
                    downloadBoardFailed.set(true);
                    encryptLatch.countDown();
                }
            });


        TestCase.assertTrue(encryptLatch.await(20, TimeUnit.SECONDS));


        TestCase.assertNotSame("Failed and complete must be different.", downloadBoardFailed.get(), downloadBoardCompleted.get());
        TestCase.assertTrue("Complete method called in DownloadOperationListener", downloadBoardCompleted.get());
        TestCase.assertFalse("Not failed.", downloadBoardFailed.get());

        //
        // Validate result points against plainText points.
        //

        for (int t = 0; t < plainText1.length; t++)
        {
            plain1.remove(resultText1[t]);
            plain2.remove(resultText2[t]);
        }

        TestCase.assertTrue(plain1.isEmpty());
        TestCase.assertTrue(plain2.isEmpty());

        NodeTestUtil.shutdownNodes();
        client.shutdown();
        commandService.shutdown();
    }

    @Test
    public void testKeyGenerationEncryptionTestWithDecryptionAndZKP()
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();
        handler.squelchType(SocketException.class);

        //
        // Set up nodes.
        //

        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml", handler);
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

        int numberOfPoints = 20; // Adjust number of points to test here.


        final ECPoint[] plainText1 = new ECPoint[numberOfPoints];
        final ECPoint[] plainText2 = new ECPoint[numberOfPoints];
        Set<ECPoint> plain1 = new HashSet<>();
        Set<ECPoint> plain2 = new HashSet<>();

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


        final ECPoint[] resultText1 = new ECPoint[plainText1.length];
        final ECPoint[] resultText2 = new ECPoint[plainText2.length];
        final AtomicBoolean downloadBoardCompleted = new AtomicBoolean(false);
        final AtomicBoolean downloadBoardFailed = new AtomicBoolean(false);
        final CountDownLatch encryptLatch = new CountDownLatch(1);
        final AtomicReference<Thread> decryptThread = new AtomicReference<>();

        ByteArrayOutputStream logStream = new ByteArrayOutputStream();

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents(
            "FRED",
            new DownloadOptions.Builder()
                .withKeyID("ECKEY")
                .withThreshold(4)
                .withNodes("A", "B", "C", "D", "E").build(),
            new DownloadOperationListener()
            {
                int counter = 0;

                @Override
                public void messageDownloaded(int index, byte[] message, List<byte[]> proofs)
                {
                    PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);
                    resultText1[counter] = decrypted.getECPoints()[0];
                    resultText2[counter++] = decrypted.getECPoints()[1];
                    TestUtil.checkThread(decryptThread);
                }

                @Override
                public void completed()
                {
                    downloadBoardCompleted.set(true);
                    TestUtil.checkThread(decryptThread);
                    encryptLatch.countDown();
                }

                @Override
                public void status(String statusObject)
                {
                    TestUtil.checkThread(decryptThread);
                }

                @Override
                public void failed(String errorObject)
                {
                    TestUtil.checkThread(decryptThread);
                    downloadBoardFailed.set(true);
                    encryptLatch.countDown();
                }
            });


        TestCase.assertTrue(encryptLatch.await(20, TimeUnit.SECONDS));

        TestCase.assertNotSame("Failed and complete must be different.", downloadBoardFailed.get(), downloadBoardCompleted.get());
        TestCase.assertTrue("Complete method not called in DownloadOperationListener", downloadBoardCompleted.get());
        TestCase.assertFalse("Not failed.", downloadBoardFailed.get());

        ECDecryptionChallengeVerifier verifier = new ECDecryptionChallengeVerifier(pubKey, new ByteArrayInputStream(logStream.toByteArray()));

        verifier.verify();

        //
        // Validate result points against plainText points.
        //

        for (int t = 0; t < plainText1.length; t++)
        {
            plain1.remove(resultText1[t]);
            plain2.remove(resultText2[t]);
        }

        TestCase.assertTrue(plain1.isEmpty());
        TestCase.assertTrue(plain2.isEmpty());

        NodeTestUtil.shutdownNodes();
        client.shutdown();
        commandService.shutdown();
    }

    @Test
    public void testKeyGenerationEncryptionTest()
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();

        handler.squelchType(SocketException.class);
        //handler.squelchType(SocketException.class);


        //
        // Set up nodes.
        //

        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml", handler);
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

        int numberOfPoints = 1; // Adjust number of points to test here.


        final ECPoint[] plainText1 = new ECPoint[numberOfPoints];
        final ECPoint[] plainText2 = new ECPoint[numberOfPoints];


        //
        // Encrypt and submit.
        //
        for (int i = 0; i < plainText1.length; i++)
        {
            plainText1[i] = generatePoint(pubKey.getParameters(), random);
            plainText2[i] = generatePoint(pubKey.getParameters(), random);

            PairSequence encrypted = new PairSequence(new ECPair[]{encryptor.encrypt(plainText1[i]), encryptor.encrypt(plainText2[i])});

            client.uploadMessage("FRED", encrypted.getEncoded());
        }

        final ECPoint[] resultText1 = new ECPoint[plainText1.length];
        final ECPoint[] resultText2 = new ECPoint[plainText2.length];
        final ValueObject<Boolean> downloadBoardCompleted = new ValueObject<Boolean>(false);
        final ValueObject<Boolean> downloadBoardFailed = new ValueObject<Boolean>(false);
        final CountDownLatch encryptLatch = new CountDownLatch(1);
        final ValueObject<Thread> decryptThread = new ValueObject<>();

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents(
            "FRED",
            new DownloadOptions.Builder()
                .withKeyID("ECKEY")
                .withThreshold(4)
                .withNodes("A", "B", "C", "D", "E").build(),
            new DownloadOperationListener()
            {
                int counter = 0;

                @Override
                public void messageDownloaded(int index, byte[] message,  List<byte[]> proofs)
                {
                    PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);
                    resultText1[counter] = decrypted.getECPoints()[0];
                    resultText2[counter++] = decrypted.getECPoints()[1];
                }

                @Override
                public void completed()
                {
                    downloadBoardCompleted.set(true);
                    decryptThread.set(Thread.currentThread());
                    encryptLatch.countDown();
                }

                @Override
                public void status(String statusObject)
                {
                    //To change body of implemented methods use File | Settings | File Templates.
                }

                @Override
                public void failed(String errorObject)
                {
                    downloadBoardFailed.set(true);
                    encryptLatch.countDown();
                }
            });


        TestCase.assertTrue(encryptLatch.await(20, TimeUnit.SECONDS));


        TestCase.assertNotSame("Failed and complete must be different.", downloadBoardFailed.get(), downloadBoardCompleted.get());
        TestCase.assertTrue("Complete method called in DownloadOperationListener", downloadBoardCompleted.get());
        TestCase.assertFalse("Not failed.", downloadBoardFailed.get());

//        TestCase.assertEquals("Shuffle and decrypt threads different.",decryptThread.get(), shuffleThread.get());


        //
        // Validate result points against plainText points.
        //

        for (int t = 0; t < plainText1.length; t++)
        {

            NodeTestUtil.printHexln("PT 1", plainText1[0].getEncoded());
            NodeTestUtil.printHexln("RT 1", resultText1[0].getEncoded());

            NodeTestUtil.printHexln("PT 2", plainText2[0].getEncoded());
            NodeTestUtil.printHexln("RT 2", resultText2[0].getEncoded());


            TestCase.assertTrue(plainText1[t].equals(resultText1[t]));
            TestCase.assertTrue(plainText2[t].equals(resultText2[t]));
        }


        NodeTestUtil.shutdownNodes();
        client.shutdown();
        commandService.shutdown();


    }


}
