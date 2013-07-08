package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.board.asn1.PairSequence;
import org.cryptoworkshop.ximix.common.board.asn1.PointSequence;
import org.cryptoworkshop.ximix.common.operation.Operation;
import org.cryptoworkshop.ximix.crypto.KeyGenerationOptions;
import org.cryptoworkshop.ximix.crypto.KeyType;
import org.cryptoworkshop.ximix.crypto.client.KeyGenerationService;
import org.cryptoworkshop.ximix.mixnet.DownloadOptions;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;
import org.cryptoworkshop.ximix.mixnet.admin.CommandService;
import org.cryptoworkshop.ximix.mixnet.admin.DownloadOperationListener;
import org.cryptoworkshop.ximix.mixnet.admin.ShuffleOperationListener;
import org.cryptoworkshop.ximix.mixnet.client.UploadService;
import org.cryptoworkshop.ximix.mixnet.transform.MultiColumnRowTransform;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.cryptoworkshop.ximix.test.node.SquelchingThrowableHandler;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.cryptoworkshop.ximix.test.node.NodeTestUtil.getXimixNode;

/**
 *
 */
public class KeyProcessingTest extends TestCase
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
    public void testKeyGenerationEncryptionTest()
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();

        handler.setPrintOnly(true);
        //handler.squelchType(SocketException.class);


        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne, true);


        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo, true);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree, true);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour, true);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml", handler);
        NodeTestUtil.launch(nodeFive, true);


        SecureRandom random = new SecureRandom();

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"));

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(KeyType.EC_ELGAMAL, "secp256r1")
            .withThreshold(4)
            .withNodes("A", "B", "C", "D", "E")
            .build();

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

        UploadService client = adminRegistrar.connect(UploadService.class);

        final ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        final ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);

        // set up 100 random messages
        final ECPoint[] plainText1 = new ECPoint[1];
        final ECPoint[] plainText2 = new ECPoint[1];

        for (int i = 0; i != plainText1.length; i++)
        {
            plainText1[i] = generatePoint(pubKey.getParameters(), random);
            plainText2[i] = generatePoint(pubKey.getParameters(), random);

            PairSequence encrypted = new PairSequence(new ECPair[]{encryptor.encrypt(plainText1[i]), encryptor.encrypt(plainText2[i])});

            client.uploadMessage("FRED", encrypted.getEncoded());
        }

        CommandService commandService = adminRegistrar.connect(CommandService.class);

        Operation<ShuffleOperationListener> shuffleOp = commandService.doShuffleAndMove("FRED", new ShuffleOptions.Builder(MultiColumnRowTransform.NAME).setKeyID("ECKEY").build(), "A", "B", "C", "D", "E");

        shuffleOp.addListener(new ShuffleOperationListener()
        {
            @Override
            public void completed()
            {
                System.err.println("done");
            }

            @Override
            public void failed(String errorObject)
            {
                System.err.println("failed: " + errorObject);
            }
        });

        final ECPoint[] resultText1 = new ECPoint[plainText1.length];
        final ECPoint[] resultText2 = new ECPoint[plainText2.length];
        final AtomicBoolean completed = new AtomicBoolean(false);

        Operation<DownloadOperationListener> op = commandService.downloadBoardContents("FRED", new DownloadOptions.Builder().setKeyID("ECKEY").setThreshold(4).build(), new DownloadOperationListener()
        {
            int counter = 0;

            @Override
            public void messageDownloaded(byte[] message)
            {
                PointSequence decrypted = PointSequence.getInstance(pubKey.getParameters().getCurve(), message);
                resultText1[counter] = decrypted.getECPoints()[0];
                resultText2[counter++] = decrypted.getECPoints()[1];
            }

            @Override
            public void completed()
            {
                completed.set(true);
            }

            @Override
            public void failed(String errorObject)
            {
                TestCase.fail("Fail called from within downloadBoardContent callback.");
            }
        });


        TestCase.assertTrue("Complete method called in DownloadOperationListener", completed.get());
        for (int t = 0; t < plainText1.length; t++)
        {
            TestCase.assertEquals(plainText1[t], resultText1[t]);
            TestCase.assertEquals(plainText2[t], resultText2[t]);
        }



//        NodeTestUtil.shutdownNodes();
//
//        keyGenerationService.close(new ThrowableListener()
//        {
//
//            @Override
//            public void notify(Throwable throwable)
//            {
//                throwable.printStackTrace();
//            }
//        });
//
//        TestCase.assertTrue(true);


    }

}
