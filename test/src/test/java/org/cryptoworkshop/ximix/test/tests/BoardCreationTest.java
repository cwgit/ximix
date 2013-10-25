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

import java.math.BigInteger;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import junit.framework.TestCase;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.BoardCreationOptions;
import org.cryptoworkshop.ximix.client.BoardCreationService;
import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.DownloadOperationListener;
import org.cryptoworkshop.ximix.client.DownloadOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.QueryService;
import org.cryptoworkshop.ximix.client.UploadService;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.Operation;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.cryptoworkshop.ximix.test.node.SquelchingThrowableHandler;
import org.cryptoworkshop.ximix.test.node.TestNotifier;
import org.junit.Test;

import static org.cryptoworkshop.ximix.test.node.NodeTestUtil.getXimixNode;

/**
 *
 */
public class BoardCreationTest
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

    }

    @Test
    public void testNameExceptions()
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

        BoardCreationService boardCreationService = adminRegistrar.connect(BoardCreationService.class);

        try
        {
            boardCreationService.createBoard("BBOARD1/X", new BoardCreationOptions.Builder("B").build());
            fail("invalid name '/' recognised");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }

        try
        {
            boardCreationService.createBoard("BBOARD1.X", new BoardCreationOptions.Builder("B").build());
            fail("invalid name '.' recognised");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }

        try
        {
            boardCreationService.createBoard("BBOARD1:X", new BoardCreationOptions.Builder("B").build());
            fail("invalid name ':' recognised");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }

        NodeTestUtil.shutdownNodes();

        boardCreationService.shutdown();
    }

    @Test
    public void testWithBuildWithMixedMissingFromGeneration()
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


        BoardCreationService boardCreationService = adminRegistrar.connect(BoardCreationService.class);

        boardCreationService.createBoard("BBOARD1", new BoardCreationOptions.Builder("B").build());
        boardCreationService.createBoard("BBOARD2", new BoardCreationOptions.Builder("B").build());

        boardCreationService.createBoard("CBOARD1", new BoardCreationOptions.Builder("C").build());

        QueryService queryService = adminRegistrar.connect(QueryService.class);

        TestCase.assertTrue(queryService.isBoardExisting("BBOARD1"));

        UploadService client = adminRegistrar.connect(UploadService.class);
        CommandService commandService = adminRegistrar.connect(CommandService.class);

        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        doMixedMissingTest(client, commandService, pubKey, new String[] { "A", "B", "C" });
        doMixedMissingTest(client, commandService, pubKey, new String[] { "C", "D", "E" });
        doMixedMissingTest(client, commandService, pubKey, new String[] { "A", "D", "E" });
        doMixedMissingTest(client, commandService, pubKey, new String[] { "A", "D", "B" });

        NodeTestUtil.shutdownNodes();
        client.shutdown();
        commandService.shutdown();
    }

     @Test
     public void testWithBuildWithMixedMissingWithBackup()
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

         BoardCreationService boardCreationService = adminRegistrar.connect(BoardCreationService.class);

         boardCreationService.createBoard("BBOARD1", new BoardCreationOptions.Builder("B").withBackUpHost("A").build());
         boardCreationService.createBoard("BBOARD2", new BoardCreationOptions.Builder("B").withBackUpHost("C").build());

         boardCreationService.createBoard("CBOARD1", new BoardCreationOptions.Builder("C").withBackUpHost("B").build());

         UploadService client = adminRegistrar.connect(UploadService.class);
         CommandService commandService = adminRegistrar.connect(CommandService.class);

         ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

         doMixedMissingTest(client, commandService, pubKey, new String[] { "A", "B", "C" });

         NodeTestUtil.shutdownNodes();
         client.shutdown();
         commandService.shutdown();
     }

    private void doMixedMissingTest(final UploadService client, CommandService commandService, final ECPublicKeyParameters pubKey, String[] decNodes)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);

        //
        // Set up plain text and upload encrypted pair.
        //

        int numberOfPoints = 100; // Adjust number of points to test here.


        final ECPoint[] plainText1 = new ECPoint[numberOfPoints];
        final ECPoint[] plainText2 = new ECPoint[numberOfPoints];

        Executor executor = Executors.newFixedThreadPool(4);

        //
        // Encrypt and submit.
        //
        final CountDownLatch bb1Latch = new CountDownLatch(plainText1.length);
        final CountDownLatch bb2Latch = new CountDownLatch(plainText1.length);
        final CountDownLatch cc1Latch = new CountDownLatch(plainText1.length);

        for (int i = 0; i < plainText1.length; i++)
        {
            plainText1[i] = generatePoint(pubKey.getParameters(), random);
            plainText2[i] = generatePoint(pubKey.getParameters(), random);

            final byte[] encrypted = new PairSequence(new ECPair[]{encryptor.encrypt(plainText1[i]), encryptor.encrypt(plainText2[i])}).getEncoded();

            executor.execute(new Runnable()
            {
                @Override
                public void run()
                {
                    try
                    {
                        client.uploadMessage("BBOARD1", encrypted);
                    }
                    catch (ServiceConnectionException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    bb1Latch.countDown();
                }
            });
            executor.execute(new Runnable()
            {
                @Override
                public void run()
                {
                    try
                    {
                        client.uploadMessage("BBOARD2", encrypted);
                    }
                    catch (ServiceConnectionException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    bb2Latch.countDown();
                }
            });
            executor.execute(new Runnable()
            {
                @Override
                public void run()
                {
                    try
                    {
                        client.uploadMessage("CBOARD1", encrypted);
                    }
                    catch (ServiceConnectionException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    cc1Latch.countDown();
                }
            });
        }

        bb1Latch.await();
        bb2Latch.await();
        cc1Latch.await();

        final ECPoint[] resultText1 = new ECPoint[plainText1.length];
        final ECPoint[] resultText2 = new ECPoint[plainText2.length];
        final AtomicBoolean downloadBoardCompleted = new AtomicBoolean(false);
        final AtomicBoolean downloadBoardFailed = new AtomicBoolean(false);
        final CountDownLatch encryptLatch = new CountDownLatch(1);
        final AtomicReference<Thread> decryptThread = new AtomicReference<>();

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents(
            "BBOARD1",
            new DownloadOptions.Builder()
                .withKeyID("ECKEY")
                .withThreshold(3)
                .withNodes(decNodes).build(),
            new DownloadOperationListener()
            {
                int counter = 0;

                @Override
                public void messageDownloaded(int index, byte[] message)
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


        TestCase.assertTrue(encryptLatch.await(30, TimeUnit.SECONDS));

        TestCase.assertNotSame("Failed and complete must be different.", downloadBoardFailed.get(), downloadBoardCompleted.get());
        TestCase.assertTrue("Complete method called in DownloadOperationListener", downloadBoardCompleted.get());
        TestCase.assertFalse("Not failed.", downloadBoardFailed.get());

      //  TestCase.assertEquals("Shuffle and decrypt threads different.", decryptThread.get(), shuffleThread.get());


        //
        // Validate result points against plainText points.
        //

        Set<ECPoint> pt = new HashSet<>();
        for (int t = 0; t < plainText1.length; t++)
        {
            pt.add(plainText1[t]);
            pt.add(plainText2[t]);
        }

        for (int t = 0; t < plainText1.length; t++)
        {
            pt.remove(resultText1[t]);
            pt.remove(resultText2[t]);
        }

        TestCase.assertEquals(0, pt.size());
    }
}
