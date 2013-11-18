package org.cryptoworkshop.ximix.node.crypto.test;

import java.io.File;
import java.math.BigInteger;
import java.security.Security;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PrivateKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.crypto.key.BLSKeyManager;
import org.cryptoworkshop.ximix.node.crypto.key.message.BLSCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.crypto.key.util.SubjectPublicKeyInfoFactory;
import org.cryptoworkshop.ximix.node.service.Decoupler;
import org.cryptoworkshop.ximix.node.service.ListeningSocketInfo;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.cryptoworkshop.ximix.node.service.NodeService;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;
import org.cryptoworkshop.ximix.node.service.ThresholdKeyPairGenerator;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 */
public class BLSKeyManagerTest
{
    private static char[] passwd = "Hello World!".toCharArray();

    @BeforeClass
    public static void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testDuplicateKey()
    {
        BLSKeyManager keyManager = new BLSKeyManager(new MyNodeContext("Test1"));

        keyManager.generateKeyPair("Test1", null, 1, new NamedKeyGenParams("Test1", null, BigInteger.ONE, "d62003-159-158.param", 1, Collections.EMPTY_LIST));

        try
        {
            keyManager.generateKeyPair("Test1", null, 1, new NamedKeyGenParams("Test1", null, BigInteger.ONE, "d62003-159-158.param", 1, Collections.EMPTY_LIST));


            Assert.fail("duplicate key not detected");
        }
        catch (IllegalStateException e)
        {
            Assert.assertEquals("Key Test1 already exists.", e.getMessage());
        }
    }


//    @Test
//    public void testFailedCommitment()
//        throws Exception
//    {
//
//        List<String> nodeNames = Arrays.asList(new String[]{"foo", "bar"});
//
//
//        BLSKeyManager keyManager = new BLSKeyManager(new MyNodeContext("foo"));
//
//        ECKeyGenParams ecKeyGenParams = new ECKeyGenParams("Test1", Algorithm.EC_ELGAMAL, BigInteger.ONE, "secp256r1", 2, nodeNames);
//
//        AsymmetricCipherKeyPair kp = keyManager.generateKeyPair("Test1", null, ecKeyGenParams.getNodesToUse().size(), ecKeyGenParams);
//        BLS01PrivateKeyParameters privKey = (BLS01PrivateKeyParameters)kp.getPrivate();
//        BLS01PublicKeyParameters pubKey = (BLS01PublicKeyParameters)kp.getPublic();
//
//        BLSNewDKGSecretSplitter secretSplitter = new BLSNewDKGSecretSplitter(
//            ecKeyGenParams.getNodesToUse().size(),
//            ecKeyGenParams.getThreshold(),
//            ecKeyGenParams.getH(),
//            privKey.getParameters(), new SecureRandom());
//
//
//        BLSCommittedSplitSecret splitSecret = secretSplitter.split(privKey.getSk().toBigInteger());
//        BLSCommittedSecretShare[] shares = splitSecret.getCommittedShares();
//
//
//        BigInteger[] aCoefficients = splitSecret.getCoefficients();
//        Element[] qCommitments = new Element[aCoefficients.length];
//
//        for (int i = 0; i != qCommitments.length; i++)
//        {
//            qCommitments[i] = privKey.getParameters().getG().duplicate().mul(aCoefficients[i]);
//        }
//
//
//        try
//        {
//
//            BLSCommittedSecretShareMessage messages = new BLSCommittedSecretShareMessage(0, shares[0].getValue(), shares[0].getWitness(), shares[0].getCommitmentFactors(),
//                ((BLS01PublicKeyParameters)kp.getPublic()).getPk());
//
//            keyManager.buildSharedKey("Test1", messages);
//
//            Assert.fail("bad commitment not detected");
//        }
//        catch (IllegalStateException e)
//        {
//            Assert.assertEquals("Commitment for Test1 failed!", e.getMessage());
//        }
//    }


    @Test
    public void testSingleKeyStoreAndLoad()
        throws Exception
    {
        BLSKeyManager keyManager = new BLSKeyManager(new MyNodeContext("foo"));
        AsymmetricCipherKeyPair kp = keyManager.generateKeyPair("Test1", Algorithm.BLS, 1, new NamedKeyGenParams("Test1", Algorithm.BLS, BigInteger.ONE, "d62003-159-158.param", 1, Collections.EMPTY_LIST));
        BLS01PrivateKeyParameters privKey = (BLS01PrivateKeyParameters)kp.getPrivate();
        BLS01PublicKeyParameters pubKey = (BLS01PublicKeyParameters)kp.getPublic();
//        ECPoint h = pubKey.getParameters().getG().multiply(BigInteger.ONE);
//        ECPoint commitment = pubKey.getParameters().getG().multiply(privKey.getD()).add(h);

        keyManager.buildSharedKey("Test1", new BLSCommittedSecretShareMessage(0, privKey.getSk().toBigInteger(), BigInteger.ONE, new Element[] { pubKey.getPk() }, pubKey.getPk()));

        keyManager.fetchPublicKey("Test1"); // make sure we've synced up

        byte[] p12enc = keyManager.getEncoded(passwd);

//        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");   TODO: maybe - can't really support these in the JCA at the moment
//
//        keyStore.load(new ByteArrayInputStream(p12enc), passwd);
//
//        Assert.assertEquals(1, keyStore.size());
//
//        Assert.assertTrue(keyStore.containsAlias("Test1"));

        BLSKeyManager rebuiltKeyManager = new BLSKeyManager(new MyNodeContext("foo"));

        rebuiltKeyManager.load(passwd, p12enc);

        Assert.assertTrue(keyManager.isSigningKey("Test1"));
        Assert.assertTrue(rebuiltKeyManager.isSigningKey("Test1"));
        Assert.assertEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((BLS01PublicKeyParameters)kp.getPublic()), keyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(((BLS01PrivateKeyParameters)kp.getPrivate()).getSk().toBigInteger(), keyManager.getPartialPrivateKey("Test1"));
        Assert.assertEquals(keyManager.fetchPublicKey("Test1"), rebuiltKeyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(keyManager.getPartialPrivateKey("Test1"), rebuiltKeyManager.getPartialPrivateKey("Test1"));
    }


    private class MyNodeContext
        implements NodeContext
    {
        private final String name;

        public MyNodeContext(String name)
        {
            this.name = name;
        }

        @Override
        public String getName()
        {
            return name;
        }

        @Override
        public Map<String, ServicesConnection> getPeerMap()
        {
            return null;
        }

        @Override
        public CapabilityMessage[] getCapabilities()
        {
            return new CapabilityMessage[0];
        }

        @Override
        public SubjectPublicKeyInfo getPublicKey(String keyID)
        {
            return null;
        }

        @Override
        public boolean hasPrivateKey(String keyID)
        {
            return false;
        }

        @Override
        public PartialPublicKeyInfo getPartialPublicKey(String keyID)
        {
            return null;
        }

        @Override
        public PrivateKeyOperator getPrivateKeyOperator(String keyID)
        {
            return null;
        }

        @Override
        public boolean shutdown(int time, TimeUnit timeUnit)
            throws InterruptedException
        {
            return false;
        }

        @Override
        public boolean isStopCalled()
        {
            return false;
        }

        @Override
        public void execute(Runnable task)
        {

        }

        @Override
        public void schedule(Runnable task, long time, TimeUnit timeUnit)
        {

        }

        @Override
        public Executor getDecoupler(Decoupler task)
        {
            return Executors.newSingleThreadExecutor();
        }

        @Override
        public ScheduledExecutorService getScheduledExecutorService()
        {
            return Executors.newScheduledThreadPool(5);
        }

        @Override
        public ThresholdKeyPairGenerator getKeyPairGenerator(Algorithm algorithm)
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public String getBoardHost(String boardName)
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public File getHomeDirectory()
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public Map<NodeService, Map<String, Object>> getServiceStatistics()
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public Map<String, String> getDescription()
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public ListeningSocketInfo getListeningSocketInfo()
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }


        @Override
        public EventNotifier getEventNotifier()
        {

            return new TestNotifier();
        }

        @Override
        public ExecutorService getExecutorService()
        {
            return getScheduledExecutorService();
        }
    }

}
