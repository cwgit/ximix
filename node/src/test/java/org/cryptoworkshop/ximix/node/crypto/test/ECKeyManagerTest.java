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
package org.cryptoworkshop.ximix.node.crypto.test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Security;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.crypto.key.ECKeyManager;
import org.cryptoworkshop.ximix.node.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.service.Decoupler;
import org.cryptoworkshop.ximix.node.service.ListeningSocketInfo;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.cryptoworkshop.ximix.node.service.NodeService;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;
import org.cryptoworkshop.ximix.node.service.ThresholdKeyPairGenerator;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ECKeyManagerTest
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
        ECKeyManager keyManager = new ECKeyManager(new MyNodeContext());

        keyManager.generateKeyPair("Test1", Algorithm.EC_ELGAMAL, 1, new NamedKeyGenParams("Test1", Algorithm.EC_ELGAMAL, BigInteger.ONE, "secp256r1", 1, Collections.EMPTY_LIST));

        try
        {
            keyManager.generateKeyPair("Test1", Algorithm.EC_ELGAMAL, 1, new NamedKeyGenParams("Test1", Algorithm.EC_ELGAMAL, BigInteger.ONE, "secp256r1", 1, Collections.EMPTY_LIST));

            Assert.fail("duplicate key not detected");
        }
        catch (IllegalStateException e)
        {
            Assert.assertEquals("Key Test1 already exists.", e.getMessage());
        }
    }

    @Test
    public void testFailedCommitment()
        throws Exception
    {
        ECKeyManager keyManager = new ECKeyManager(new MyNodeContext());

        AsymmetricCipherKeyPair kp = keyManager.generateKeyPair("Test1", Algorithm.EC_ELGAMAL, 1, new NamedKeyGenParams("Test1", Algorithm.EC_ELGAMAL, BigInteger.ONE, "secp256r1", 1, Collections.EMPTY_LIST));
        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)kp.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)kp.getPublic();
        ECPoint h = pubKey.getParameters().getG().multiply(BigInteger.ONE);
        ECPoint commitment = pubKey.getParameters().getG().multiply(privKey.getD()).add(h);

        try
        {
            keyManager.buildSharedKey("Test1", new ECCommittedSecretShareMessage(0, privKey.getD(), BigInteger.TEN, new ECPoint[]{commitment}, pubKey.getQ(), new ECPoint[]{pubKey.getQ()}));

            Assert.fail("bad commitment not detected");
        }
        catch (IllegalStateException e)
        {
            Assert.assertEquals("Commitment for Test1 failed!", e.getMessage());
        }
    }

    @Test
    public void testSingleKeyStoreAndLoad()
        throws Exception
    {
        ECKeyManager keyManager = new ECKeyManager(new MyNodeContext());
        AsymmetricCipherKeyPair kp = keyManager.generateKeyPair("Test1", Algorithm.EC_ELGAMAL, 1, new NamedKeyGenParams("Test1", Algorithm.EC_ELGAMAL, BigInteger.ONE, "secp256r1", 1, Collections.EMPTY_LIST));
        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)kp.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)kp.getPublic();
        ECPoint h = pubKey.getParameters().getG().multiply(BigInteger.ONE);
        ECPoint commitment = pubKey.getParameters().getG().multiply(privKey.getD()).add(h);

        keyManager.buildSharedKey("Test1", new ECCommittedSecretShareMessage(0, privKey.getD(), BigInteger.ONE, new ECPoint[]{commitment}, pubKey.getQ(), new ECPoint[]{pubKey.getQ()}));

        keyManager.fetchPublicKey("Test1"); // make sure we've synced up

        byte[] p12enc = keyManager.getEncoded(passwd);

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(new ByteArrayInputStream(p12enc), passwd);

        Assert.assertEquals(1, keyStore.size());

        Assert.assertTrue(keyStore.containsAlias("Test1"));

        ECKeyManager rebuiltKeyManager = new ECKeyManager(new MyNodeContext());

        rebuiltKeyManager.load(passwd, p12enc);

        Assert.assertFalse(keyManager.isSigningKey("Test1"));
        Assert.assertFalse(rebuiltKeyManager.isSigningKey("Test1"));
        Assert.assertEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()), keyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(((ECPrivateKeyParameters)kp.getPrivate()).getD(), keyManager.getPartialPrivateKey("Test1"));
        Assert.assertEquals(keyManager.fetchPublicKey("Test1"), rebuiltKeyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(keyManager.getPartialPrivateKey("Test1"), rebuiltKeyManager.getPartialPrivateKey("Test1"));
    }

    @Test
    public void testMultipleKeyStoreAndLoad()
        throws Exception
    {
        ECKeyManager keyManager = new ECKeyManager(new MyNodeContext());
        AsymmetricCipherKeyPair kp1 = keyManager.generateKeyPair("Test1", Algorithm.EC_ELGAMAL, 1, new NamedKeyGenParams("Test1", Algorithm.EC_ELGAMAL, BigInteger.ONE, "secp256r1", 1, Collections.EMPTY_LIST));
        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)kp1.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)kp1.getPublic();
        ECPoint h = pubKey.getParameters().getG().multiply(BigInteger.ONE);
        ECPoint commitment = pubKey.getParameters().getG().multiply(privKey.getD()).add(h);

        keyManager.buildSharedKey("Test1", new ECCommittedSecretShareMessage(0, privKey.getD(), BigInteger.ONE, new ECPoint[]{commitment}, pubKey.getQ(), new ECPoint[]{pubKey.getQ()}));

        AsymmetricCipherKeyPair kp2 = keyManager.generateKeyPair("Test2", Algorithm.ECDSA, 1, new NamedKeyGenParams("Test1", Algorithm.ECDSA, BigInteger.ONE, "secp256r1", 1, Collections.EMPTY_LIST));
        privKey = (ECPrivateKeyParameters)kp2.getPrivate();
        pubKey = (ECPublicKeyParameters)kp2.getPublic();
        commitment = pubKey.getParameters().getG().multiply(privKey.getD()).add(h);
        keyManager.buildSharedKey("Test2", new ECCommittedSecretShareMessage(0, privKey.getD(), BigInteger.ONE, new ECPoint[]{commitment}, pubKey.getQ(), new ECPoint[]{pubKey.getQ()}));

        keyManager.fetchPublicKey("Test1"); // make sure we've synced up
        keyManager.fetchPublicKey("Test2"); // make sure we've synced up

        byte[] p12enc = keyManager.getEncoded(passwd);

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(new ByteArrayInputStream(p12enc), passwd);

        Assert.assertEquals(2, keyStore.size());

        Assert.assertTrue(keyStore.containsAlias("Test1"));
        Assert.assertTrue(keyStore.containsAlias("Test2"));

        ECKeyManager rebuiltKeyManager = new ECKeyManager(new MyNodeContext());

        rebuiltKeyManager.load(passwd, p12enc);

        Assert.assertFalse(keyManager.isSigningKey("Test1"));
        Assert.assertFalse(rebuiltKeyManager.isSigningKey("Test1"));
        Assert.assertTrue(keyManager.isSigningKey("Test2"));
        Assert.assertTrue(rebuiltKeyManager.isSigningKey("Test2"));
        Assert.assertEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp1.getPublic()), keyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp2.getPublic()), keyManager.fetchPublicKey("Test2"));
        Assert.assertEquals(((ECPrivateKeyParameters)kp1.getPrivate()).getD(), keyManager.getPartialPrivateKey("Test1"));
        Assert.assertEquals(((ECPrivateKeyParameters)kp2.getPrivate()).getD(), keyManager.getPartialPrivateKey("Test2"));
        Assert.assertEquals(keyManager.fetchPublicKey("Test1"), rebuiltKeyManager.fetchPublicKey("Test1"));
        Assert.assertEquals(keyManager.getPartialPrivateKey("Test1"), rebuiltKeyManager.getPartialPrivateKey("Test1"));
        Assert.assertEquals(keyManager.fetchPublicKey("Test2"), rebuiltKeyManager.fetchPublicKey("Test2"));
        Assert.assertEquals(keyManager.getPartialPrivateKey("Test2"), rebuiltKeyManager.getPartialPrivateKey("Test2"));
    }

    private class MyNodeContext
        implements NodeContext
    {
        @Override
        public String getName()
        {
            return "Test";
        }

        @Override
        public Map<String, ServicesConnection> getPeerMap()
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public CapabilityMessage[] getCapabilities()
        {
            return new CapabilityMessage[0];
        }

        @Override
        public SubjectPublicKeyInfo getPublicKey(String keyID)
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public boolean hasPrivateKey(String keyID)
        {
            return false;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public PartialPublicKeyInfo getPartialPublicKey(String keyID)
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public PrivateKeyOperator getPrivateKeyOperator(String keyID)
        {
            return null;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public boolean shutdown(int time, TimeUnit timeUnit)
            throws InterruptedException
        {
            return false;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public boolean isStopCalled()
        {
            return false;  //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public void execute(Runnable task)
        {
            //To change body of implemented methods use File | Settings | File Templates.
        }

        @Override
        public void schedule(Runnable task, long time, TimeUnit timeUnit)
        {
            //To change body of implemented methods use File | Settings | File Templates.
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
