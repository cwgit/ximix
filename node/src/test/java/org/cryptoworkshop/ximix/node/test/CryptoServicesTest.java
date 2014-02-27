package org.cryptoworkshop.ximix.node.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.ec.ECDecryptor;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.connection.AdminServicesConnection;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.client.connection.signing.BLSSigningService;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequenceWithProofs;
import org.cryptoworkshop.ximix.common.asn1.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.asn1.message.KeyPairGenerateMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageDataBlock;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureCreateMessage;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.crypto.threshold.ECCommittedSecretShare;
import org.cryptoworkshop.ximix.common.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.core.XimixNodeContext;
import org.cryptoworkshop.ximix.node.crypto.key.BLSKeyPairGenerator;
import org.cryptoworkshop.ximix.node.crypto.key.ECKeyPairGenerator;
import org.cryptoworkshop.ximix.node.crypto.key.ECNewDKGGenerator;
import org.cryptoworkshop.ximix.node.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.crypto.key.util.BLSPublicKeyFactory;
import org.cryptoworkshop.ximix.node.crypto.test.TestNotifier;
import org.cryptoworkshop.ximix.node.service.NodeService;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class CryptoServicesTest
{
    static
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testBasicGenerationNoPeers()
        throws Exception
    {
        XimixNodeContext context = new XimixNodeContext(new HashMap<String, ServicesConnection>(), new Config(createConfig("A")), new TestNotifier());

        try
        {
            List<String> peers = Arrays.asList("A", "B", "C");
            NamedKeyGenParams kGenParams = new NamedKeyGenParams("EC_KEY", Algorithm.EC_ELGAMAL, "secp256r1", 4, peers);
            X9ECParameters ecParameters = CustomNamedCurves.getByName("secp256r1");
            ECDomainParameters domainParameters = new ECDomainParameters(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN(), ecParameters.getH());
            ECPoint h = domainParameters.getG().multiply(BigInteger.valueOf(1000001));
            ECCommittedSecretShareMessage[] messages = ((ECNewDKGGenerator)context.getKeyPairGenerator(Algorithm.EC_ELGAMAL))
                .generateThresholdKey("EC_KEY", domainParameters, kGenParams.getNodesToUse().size(), kGenParams.getThreshold(), h);

            Assert.fail("no exception!");
        }
        catch (IllegalArgumentException e)
        {
            if (!"numberOfPeers must at least be as big as the threshold value.".equals(e.getMessage()))
            {
                Assert.fail("exception but wrong message");
            }
        }
    }

    @Test
    public void testBasicGeneration()
        throws Exception
    {
        Map<String, XimixNodeContext>  contextMap = createContextMap(5);

        XimixNodeContext context = contextMap.get("A");

        List<String> peers = Arrays.asList("A", "B", "C", "D", "E");
        NamedKeyGenParams kGenParams = new NamedKeyGenParams("EC_KEY", Algorithm.EC_ELGAMAL, "secp256r1", 4, peers);
        X9ECParameters ecParameters = CustomNamedCurves.getByName("secp256r1");
        ECDomainParameters domainParameters = new ECDomainParameters(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN(), ecParameters.getH());
        ECPoint h = domainParameters.getG().multiply(BigInteger.valueOf(1000001));
        ECCommittedSecretShareMessage[] messages = ((ECNewDKGGenerator)context.getKeyPairGenerator(Algorithm.EC_ELGAMAL))
            .generateThresholdKey("EC_KEY", domainParameters, kGenParams.getNodesToUse().size(), kGenParams.getThreshold(), h);
        Assert.assertEquals(5, messages.length);

        X9ECParameters params = CustomNamedCurves.getByName("secp256r1");
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());

        for (int i = 0; i != messages.length; i++)
        {
            ECCommittedSecretShareMessage message = ECCommittedSecretShareMessage.getInstance(params.getCurve(), messages[i].getEncoded());
            ECCommittedSecretShare share = new ECCommittedSecretShare(message.getValue(), message.getWitness(), message.getCommitmentFactors());

            Assert.assertTrue(share.isRevealed(i, domainParams, h));
        }
    }

    @Test
    public void testECGenerationViaMessage()
        throws Exception
    {
        final Map<String, XimixNodeContext>  contextMap = createContextMap(5);

        XimixNodeContext context = contextMap.get("A");

        final String[] peers = new String[] { "A", "B", "C", "D", "E" };

        final NamedKeyGenParams ecKeyGenParams = new NamedKeyGenParams("ECKEY", Algorithm.EC_ELGAMAL, BigInteger.valueOf(1000001), "secp256r1", 3, Arrays.asList(peers));

        final Map<String, ServicesConnection> peerMap = new HashMap<>();

        peerMap.put("A", contextMap.get("B").getPeerMap().get("A"));
        peerMap.put("B", contextMap.get("A").getPeerMap().get("B"));
        peerMap.put("C", contextMap.get("B").getPeerMap().get("C"));
        peerMap.put("D", contextMap.get("B").getPeerMap().get("D"));
        peerMap.put("E", contextMap.get("B").getPeerMap().get("E"));

        final CountDownLatch generateLatch = new CountDownLatch(5);
        for (final String nodeName : peers)
        {
            new Thread(new Runnable()
            {
                @Override
                public void run()
                {
                    MessageReply reply = null;
                    try
                    {
                        reply = peerMap.get(nodeName).sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(Algorithm.EC_ELGAMAL, new KeyPairGenerateMessage(Algorithm.EC_ELGAMAL, ECKeyPairGenerator.Type.GENERATE, ecKeyGenParams)));
                    }
                    catch (ServiceConnectionException e)
                    {
                        e.printStackTrace();
                    }

                    Assert.assertEquals(reply.getType(), MessageReply.Type.OKAY);
                    generateLatch.countDown();
                }
            }).start();
        }

        generateLatch.await();

        SubjectPublicKeyInfo pubKeyInfo1 = context.getPublicKey("ECKEY");
        final ECPublicKeyParameters pubKey1 = (ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo1);
        SubjectPublicKeyInfo pubKeyInfo2 = contextMap.get("B").getPublicKey("ECKEY");
        ECPublicKeyParameters pubKey2 = (ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo2);

        Assert.assertEquals(pubKey1.getQ(), pubKey2.getQ());

        for (String nodeName : peers)
        {
            pubKeyInfo2 = contextMap.get(nodeName).getPublicKey("ECKEY");
            pubKey2 = (ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo2);

            Assert.assertEquals(nodeName, pubKey1.getQ(), pubKey2.getQ());
        }

                // Create a random plaintext
        ECPoint plaintext = generatePoint(pubKey1.getParameters(), new SecureRandom());

        // Encrypt it using the joint public key
        ECEncryptor enc = new ECElGamalEncryptor();

        enc.init(new ParametersWithRandom(pubKey1, new SecureRandom()));

        final ECPair cipherText = enc.encrypt(plaintext);


        // Note: ordering is important here!!!

        ECDecryptor dec = new ECDecryptor()
        {
            @Override
            public void init(CipherParameters cipherParameters)
            {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public ECPoint decrypt(ECPair ecPair)
            {
                int index = 0;
                ECPoint[] partialDecs = new ECPoint[peers.length];

                Map<String, ServicesConnection> fullMap = new HashMap<>();

                fullMap.put("A", contextMap.get("B").getPeerMap().get("A"));
                fullMap.put("B", contextMap.get("A").getPeerMap().get("B"));
                fullMap.put("C", contextMap.get("A").getPeerMap().get("C"));
                fullMap.put("D", contextMap.get("A").getPeerMap().get("D"));
                fullMap.put("E", contextMap.get("A").getPeerMap().get("E"));

                for (String nodeName : peers)
                {
                    MessageReply decReply = null;
                    try
                    {
                        decReply = fullMap.get(nodeName).sendMessage(CommandMessage.Type.PARTIAL_DECRYPT, new DecryptDataMessage("ECKEY", Collections.singletonList(new PairSequence(cipherText).getEncoded())));

                        partialDecs[index++] = PairSequenceWithProofs.getInstance(pubKey1.getParameters().getCurve(), PostedMessageDataBlock.getInstance(ShareMessage.getInstance(decReply.getPayload()).getShareData()).getMessages().get(0)).getECPairs()[0].getX();
                    }
                    catch (ServiceConnectionException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                }

                LagrangeWeightCalculator lagrangeWeightCalculator = new LagrangeWeightCalculator(peers.length, pubKey1.getParameters().getN());

                BigInteger[] weights = lagrangeWeightCalculator.computeWeights(partialDecs);

                // weighting
                ECPoint weightedDecryption = partialDecs[0].multiply(weights[0]);
                for (int i = 1; i < weights.length; i++)
                {
                    if (partialDecs[i] != null)
                    {
                        weightedDecryption = weightedDecryption.add(partialDecs[i].multiply(weights[i]));
                    }
                }

                // Do final decryption to recover plaintext ECPoint
                return cipherText.getY().add(weightedDecryption.negate());
            }
        };

        // Do final decryption to recover plaintext ECPoint
        ECPoint decrypted = dec.decrypt(cipherText);

        Assert.assertEquals(plaintext, decrypted);
    }

    @Test
    public void testBLSGenerationViaMessage()
        throws Exception
    {
        final Map<String, XimixNodeContext> contextMap = createContextMap(5);

        XimixNodeContext context = contextMap.get("A");

        final List<String> peers = Arrays.asList("A", "B", "C", "D", "E");

        NamedKeyGenParams ecKeyGenParams = new NamedKeyGenParams("BLSKEY", Algorithm.BLS, BigInteger.valueOf(1000001), "d62003-159-158.param", 3, peers);

        Map<String, ServicesConnection> peerMap = new HashMap<>();

        peerMap.put("A", contextMap.get("B").getPeerMap().get("A"));
        peerMap.put("B", contextMap.get("A").getPeerMap().get("B"));
        peerMap.put("C", contextMap.get("B").getPeerMap().get("C"));
        peerMap.put("D", contextMap.get("B").getPeerMap().get("D"));
        peerMap.put("E", contextMap.get("B").getPeerMap().get("E"));

        for (String nodeName : peers)
        {
            MessageReply reply = peerMap.get(nodeName).sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(Algorithm.BLS, new KeyPairGenerateMessage(Algorithm.BLS, BLSKeyPairGenerator.Type.GENERATE, ecKeyGenParams)));

            Assert.assertEquals(reply.getType(), MessageReply.Type.OKAY);
        }

        SubjectPublicKeyInfo pubKeyInfo1 = context.getPublicKey("BLSKEY");
        final BLS01PublicKeyParameters pubKey1 = BLSPublicKeyFactory.createKey(pubKeyInfo1);
        SubjectPublicKeyInfo pubKeyInfo2 = contextMap.get("B").getPublicKey("BLSKEY");
        BLS01PublicKeyParameters pubKey2 = BLSPublicKeyFactory.createKey(pubKeyInfo2);

        Assert.assertEquals(pubKey1.getPk(), pubKey2.getPk());

        for (String nodeName : peers)
        {
            pubKeyInfo2 = contextMap.get(nodeName).getPublicKey("BLSKEY");
            pubKey2 = BLSPublicKeyFactory.createKey(pubKeyInfo2);

            Assert.assertEquals(nodeName, pubKey1.getPk(), pubKey2.getPk());
        }

        Pairing pairing = PairingFactory.getPairing(pubKey1.getParameters().getCurveParameters());

        // create message hash
        MessageDigest mdv = MessageDigest.getInstance("SHA1");
        byte[] hashv = mdv.digest("this is a test message".getBytes());

        final Map<String, ServicesConnection> fullMap = new HashMap<>();

        fullMap.put("A", contextMap.get("B").getPeerMap().get("A"));
        fullMap.put("B", contextMap.get("A").getPeerMap().get("B"));
        fullMap.put("C", contextMap.get("A").getPeerMap().get("C"));
        fullMap.put("D", contextMap.get("A").getPeerMap().get("D"));
        fullMap.put("E", contextMap.get("A").getPeerMap().get("E"));

        MessageReply decReply = null;
        try
        {
            BLSSigningService blsSigningService = new BLSSigningService(new AdminServicesConnection()
            {
                @Override
                public Set<String> getActiveNodeNames()
                {
                    return null;  //To change body of implemented methods use File | Settings | File Templates.
                }

                @Override
                public MessageReply sendMessage(String nodeName, MessageType type, ASN1Encodable messagePayload)
                    throws ServiceConnectionException
                {
                    return fullMap.get(nodeName).sendMessage(type, messagePayload);
                }

                @Override
                public void activate()
                    throws ServiceConnectionException
                {

                }

                @Override
                public CapabilityMessage[] getCapabilities()
                {
                    return new CapabilityMessage[0];  //To change body of implemented methods use File | Settings | File Templates.
                }

                @Override
                public EventNotifier getEventNotifier()
                {
                    return null;
                }

                @Override
                public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
                    throws ServiceConnectionException
                {
                    return fullMap.get("A").sendMessage(type, messagePayload);
                }

                @Override
                public void shutdown()
                    throws ServiceConnectionException
                {
                    //To change body of implemented methods use File | Settings | File Templates.
                }
            });

            decReply = blsSigningService.generateSig(new SignatureCreateMessage("BLSKEY", hashv, 3, "A", "B", "C", "D"));
        }
        catch (ServiceConnectionException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

        it.unisa.dia.gas.jpbc.Element finalSignature = pairing.getG1().newElement();

        Assert.assertNotNull(decReply);

        finalSignature.setFromBytes(ASN1OctetString.getInstance(decReply.getPayload()).getOctets());

        // Create verification hash

        it.unisa.dia.gas.jpbc.Element hv = pairing.getG1().newElement().setFromHash(hashv, 0, hashv.length);

        // Verify the signature
        it.unisa.dia.gas.jpbc.Element temp1 = pairing.pairing(finalSignature, pubKey1.getParameters().getG());
        it.unisa.dia.gas.jpbc.Element temp2 = pairing.pairing(hv, pubKey1.getPk());

        Assert.assertTrue("BLS signature failed", temp1.isEqual(temp2));
    }

    private Map<String, XimixNodeContext> createContextMap(int size)
        throws ConfigException
    {
        final Map<String, ServicesConnection> connectionMap = new HashMap<>();
        final Map<String, ServicesConnection>[] connectionMaps = new Map[size];
        final Map<String, XimixNodeContext> nodeMap = new HashMap<>();

        for (int i = 0; i != size; i++)
        {
            connectionMaps[i] = new HashMap<>();
        }

        for (int i = 0; i != size; i++)
        {
            final String nodeName = String.valueOf((char)('A' + i));
            final int    nodeNo = i;
            final XimixNodeContext context = new XimixNodeContext(connectionMaps[nodeNo], new Config(createConfig(nodeName)), new TestNotifier());

            nodeMap.put(nodeName, context);

            connectionMap.put(nodeName, new ServicesConnection()
            {
                @Override
                public void activate()
                    throws ServiceConnectionException
                {

                }

                @Override
                public CapabilityMessage[] getCapabilities()
                {
                    return context.getCapabilities();
                }

                @Override
                public EventNotifier getEventNotifier()
                {
                    return context.getEventNotifier();
                }

                @Override
                public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
                    throws ServiceConnectionException
                {
                    Message message;

                    if (type instanceof CommandMessage.Type)
                    {
                         message = new CommandMessage((CommandMessage.Type)type, messagePayload);
                    }
                    else
                    {
                        message = new ClientMessage((ClientMessage.Type)type, messagePayload);
                    }

                    NodeService nodeService = context.getService(message);

                    return nodeService.handle(message);
                }

                @Override
                public void shutdown() throws ServiceConnectionException
                {
                    throw new RuntimeException("Not implemented.");
                }
            });
        }

        for (int i = 0; i != size; i++)
        {
            String nodeName = String.valueOf((char)('A' + i));

            for (String node : connectionMap.keySet())
            {
                if (node.equals(nodeName))
                {
                    continue;
                }

                nodeMap.get(nodeName).getPeerMap().put(node, connectionMap.get(node));
            }
        }

        return nodeMap;
    }

    private Element createConfig(String nodeName)
    {
        try
        {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = documentBuilder.newDocument();
            Element rootElement = document.createElement("config");

            Element name = document.createElement("name");

            rootElement.appendChild(name);

            name.appendChild(document.createTextNode(nodeName));

            Element trustAnchor = document.createElement("trustAnchor");

            rootElement.appendChild(trustAnchor);

            trustAnchor.appendChild(document.createTextNode("trustCa"));

            Element keyManagerStore = document.createElement("keyManagerStore");

            rootElement.appendChild(keyManagerStore);

            keyManagerStore.appendChild(document.createTextNode("nodeCaStore"));

            Element keyManagerPassword = document.createElement("keyManagerPassword");

            rootElement.appendChild(keyManagerPassword);

            keyManagerPassword.appendChild(document.createTextNode("Hello"));

            Element portNo = document.createElement("portNo");

            rootElement.appendChild(portNo);

            portNo.appendChild(document.createTextNode("99"));

            Element portBacklog = document.createElement("portBacklog");

            rootElement.appendChild(portBacklog);

            portBacklog.appendChild(document.createTextNode("99"));

            Element portAddress = document.createElement("portAddress");

            rootElement.appendChild(portAddress);

            portAddress.appendChild(document.createTextNode("0.0.0.0"));

            Element description = document.createElement("description");
            rootElement.appendChild(description);


            Element services = document.createElement("services");
            rootElement.appendChild(services);

            Element service = document.createElement("service");
            services.appendChild(service);

            services.appendChild(createService(document, "org.cryptoworkshop.ximix.node.crypto.service.NodeKeyRetrievalService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.node.crypto.service.NodeKeyGenerationService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.node.crypto.service.NodeSigningService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.node.crypto.service.NodeDecryptionService"));

            return rootElement;
        }
        catch (Exception e)
        {
            Assert.fail("can't create config: " + e.getMessage());
            return null;
        }
    }

    private Element createService(Document document, String implementation)
    {
        Element service = document.createElement("service");

        Element implementationNode = document.createElement("implementation");
        implementationNode.appendChild(document.createTextNode(implementation));
        service.appendChild(implementationNode);

        return service;
    }

    public static BigInteger getRandomInteger(BigInteger n, SecureRandom rand)
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

    public static ECPoint generatePoint(ECDomainParameters params, SecureRandom rand)
    {
        return params.getG().multiply(getRandomInteger(params.getN(), rand));
    }
}
