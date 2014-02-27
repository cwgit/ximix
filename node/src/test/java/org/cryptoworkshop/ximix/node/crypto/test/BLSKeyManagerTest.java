package org.cryptoworkshop.ximix.node.crypto.test;

import java.math.BigInteger;
import java.security.Security;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PrivateKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cryptoworkshop.ximix.common.asn1.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.node.crypto.key.BLSKeyManager;
import org.cryptoworkshop.ximix.node.crypto.key.message.BLSCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.crypto.key.util.SubjectPublicKeyInfoFactory;
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
        BLSKeyManager keyManager = new BLSKeyManager(new TestUtils.BasicNodeContext("Test1"));

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
        TestUtils.BasicNodeContext nodeContext1 = new TestUtils.BasicNodeContext("foo");

        BLSKeyManager keyManager = new BLSKeyManager(nodeContext1);

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

        TestUtils.BasicNodeContext nodeContext2 = new TestUtils.BasicNodeContext("foo");
        BLSKeyManager rebuiltKeyManager = new BLSKeyManager(nodeContext2);

        rebuiltKeyManager.load(passwd, p12enc);

        Assert.assertTrue(keyManager.isSigningKey("Test1"));
        Assert.assertTrue(rebuiltKeyManager.isSigningKey("Test1"));
        Assert.assertEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((BLS01PublicKeyParameters)kp.getPublic()), keyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(((BLS01PrivateKeyParameters)kp.getPrivate()).getSk().toBigInteger(), keyManager.getPartialPrivateKey("Test1"));
        Assert.assertEquals(keyManager.fetchPublicKey("Test1"), rebuiltKeyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(keyManager.getPartialPrivateKey("Test1"), rebuiltKeyManager.getPartialPrivateKey("Test1"));

        nodeContext1.shutdown(0, TimeUnit.MICROSECONDS);
        nodeContext2.shutdown(0, TimeUnit.MICROSECONDS);
    }
}
