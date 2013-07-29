package org.cryptoworkshop.ximix.node.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ec.ECDecryptor;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.board.asn1.PairSequence;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.message.PostedMessageDataBlock;
import org.cryptoworkshop.ximix.common.message.ShareMessage;
import org.cryptoworkshop.ximix.common.service.Algorithm;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.crypto.key.BLSKeyPairGenerator;
import org.cryptoworkshop.ximix.crypto.key.ECKeyPairGenerator;
import org.cryptoworkshop.ximix.crypto.key.ECNewDKGGenerator;
import org.cryptoworkshop.ximix.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.crypto.key.message.ECKeyGenParams;
import org.cryptoworkshop.ximix.crypto.key.message.KeyGenParams;
import org.cryptoworkshop.ximix.crypto.key.message.KeyGenerationMessage;
import org.cryptoworkshop.ximix.crypto.key.message.KeyPairGenerateMessage;
import org.cryptoworkshop.ximix.crypto.key.util.BLSPublicKeyFactory;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSecretShare;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.node.XimixNodeContext;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class CryptoServicesTest
{
    @Test
    public void testBasicGenerationNoPeers()
        throws Exception
    {
        XimixNodeContext context = new XimixNodeContext(new HashMap<String, ServicesConnection>(), new Config(createConfig("A")));

        try
        {
            Set<String> peers = new HashSet(Arrays.asList("A", "B", "C"));
            ECKeyGenParams kGenParams = new ECKeyGenParams("EC_KEY", Algorithm.EC_ELGAMAL, BigInteger.valueOf(1000001), "secp256r1", 4, peers);
            ECCommittedSecretShareMessage[] messages = ((ECNewDKGGenerator)context.getKeyPairGenerator(Algorithm.EC_ELGAMAL)).generateThresholdKey("EC_KEY", kGenParams);

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

        Set<String> peers = new HashSet(Arrays.asList("A", "B", "C", "D", "E"));
        ECKeyGenParams kGenParams = new ECKeyGenParams("EC_KEY", Algorithm.EC_ELGAMAL, BigInteger.valueOf(1000001), "secp256r1", 4, peers);
        ECCommittedSecretShareMessage[] messages = ((ECNewDKGGenerator)context.getKeyPairGenerator(Algorithm.EC_ELGAMAL)).generateThresholdKey("EC_KEY", kGenParams);

        Assert.assertEquals(5, messages.length);

        X9ECParameters params = SECNamedCurves.getByName("secp256r1");
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());

        for (int i = 0; i != messages.length; i++)
        {
            ECCommittedSecretShareMessage message = ECCommittedSecretShareMessage.getInstance(params.getCurve(), messages[i].getEncoded());
            ECCommittedSecretShare share = new ECCommittedSecretShare(message.getValue(), message.getWitness(), message.getCommitmentFactors());

            Assert.assertTrue(share.isRevealed(i, domainParams, BigInteger.valueOf(1000001)));
        }
    }

    @Test
    public void testECGenerationViaMessage()
        throws Exception
    {
        final Map<String, XimixNodeContext>  contextMap = createContextMap(5);

        XimixNodeContext context = contextMap.get("A");

        final ServicesConnection connection = context.getPeerMap().get("B");
        final Set<String> peers = new HashSet(Arrays.asList("A", "B", "C", "D", "E"));
        final KeyGenerationMessage genKeyPairMessage = new KeyGenerationMessage(Algorithm.EC_ELGAMAL, "ECKEY", new KeyGenParams("secp256r1"), 3, peers);

        MessageReply reply = connection.sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(Algorithm.EC_ELGAMAL,
                                                          new KeyPairGenerateMessage(Algorithm.EC_ELGAMAL, ECKeyPairGenerator.Type.INITIATE, genKeyPairMessage)));

        Assert.assertEquals(reply.getType(), MessageReply.Type.OKAY);

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
                ECPoint[] partialDecs = new ECPoint[peers.size()];

                Map<String, ServicesConnection> fullMap = new HashMap<>();

                fullMap.put("A", contextMap.get("B").getPeerMap().get("A"));
                fullMap.put("B", contextMap.get("A").getPeerMap().get("B"));
                fullMap.put("C", contextMap.get("A").getPeerMap().get("C"));
                fullMap.put("D", contextMap.get("A").getPeerMap().get("D"));
                fullMap.put("E", contextMap.get("A").getPeerMap().get("E"));

                for (String nodeName : genKeyPairMessage.getNodesToUse())
                {
                    MessageReply decReply = null;
                    try
                    {
                        decReply = fullMap.get(nodeName).sendMessage(CommandMessage.Type.PARTIAL_DECRYPT, new DecryptDataMessage("ECKEY", Collections.singletonList(new PairSequence(cipherText).getEncoded())));
                    }
                    catch (ServiceConnectionException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    partialDecs[index++] = PairSequence.getInstance(pubKey1.getParameters().getCurve(), PostedMessageDataBlock.getInstance(ShareMessage.getInstance(decReply.getPayload()).getShareData()).getMessages().get(0)).getECPairs()[0].getX();
                }

                LagrangeWeightCalculator lagrangeWeightCalculator = new LagrangeWeightCalculator(peers.size(), pubKey1.getParameters().getN());

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

        final ServicesConnection connection = context.getPeerMap().get("B");
        final Set<String> peers = new HashSet(Arrays.asList("A", "B", "C", "D", "E"));
        final KeyGenerationMessage genKeyPairMessage = new KeyGenerationMessage(Algorithm.BLS, "BLSKEY", new KeyGenParams("d62003-159-158.param"), 3, peers);

        MessageReply reply = connection.sendMessage(CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(Algorithm.BLS,
                                                            new KeyPairGenerateMessage(Algorithm.BLS, BLSKeyPairGenerator.Type.INITIATE, genKeyPairMessage)));

        Assert.assertEquals(reply.getType(), MessageReply.Type.OKAY);

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

//        // Create a random plaintext
//        ECPoint plaintext = generatePoint(pubKey1.getParameters(), new SecureRandom());
//
//        // Encrypt it using the joint public key
//        ECEncryptor enc = new ECElGamalEncryptor();
//
//        enc.init(new ParametersWithRandom(pubKey1, new SecureRandom()));
//
//        final ECPair cipherText = enc.encrypt(plaintext);
//
//
//        // Note: ordering is important here!!!
//
//        ECDecryptor dec = new ECDecryptor()
//        {
//            @Override
//            public void init(CipherParameters cipherParameters)
//            {
//                //To change body of implemented methods use File | Settings | File Templates.
//            }
//
//            @Override
//            public ECPoint decrypt(ECPair ecPair)
//            {
//                int index = 0;
//                ECPoint[] partialDecs = new ECPoint[peers.size()];
//
//                Map<String, ServicesConnection> fullMap = new HashMap<>();
//
//                fullMap.put("A", contextMap.get("B").getPeerMap().get("A"));
//                fullMap.put("B", contextMap.get("A").getPeerMap().get("B"));
//                fullMap.put("C", contextMap.get("A").getPeerMap().get("C"));
//                fullMap.put("D", contextMap.get("A").getPeerMap().get("D"));
//                fullMap.put("E", contextMap.get("A").getPeerMap().get("E"));
//
//                for (String nodeName : genKeyPairMessage.getNodesToUse())
//                {
//                    MessageReply decReply = null;
//                    try
//                    {
//                        decReply = fullMap.get(nodeName).sendMessage(CommandMessage.Type.PARTIAL_DECRYPT, new DecryptDataMessage("BLSKEY", Collections.singletonList(new PairSequence(cipherText).getEncoded())));
//                    }
//                    catch (ServiceConnectionException e)
//                    {
//                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
//                    }
//                    catch (IOException e)
//                    {
//                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
//                    }
//                    partialDecs[index++] = PairSequence.getInstance(pubKey1.getParameters().getCurve(), MessageBlock.getInstance(ShareMessage.getInstance(decReply.getPayload()).getShareData()).getMessages().get(0)).getECPairs()[0].getX();
//                }
//
//                LagrangeWeightCalculator lagrangeWeightCalculator = new LagrangeWeightCalculator(peers.size(), pubKey1.getParameters().getN());
//
//                BigInteger[] weights = lagrangeWeightCalculator.computeWeights(partialDecs);
//
//                // weighting
//                ECPoint weightedDecryption = partialDecs[0].multiply(weights[0]);
//                for (int i = 1; i < weights.length; i++)
//                {
//                    if (partialDecs[i] != null)
//                    {
//                        weightedDecryption = weightedDecryption.add(partialDecs[i].multiply(weights[i]));
//                    }
//                }
//
//                // Do final decryption to recover plaintext ECPoint
//                return cipherText.getY().add(weightedDecryption.negate());
//            }
//        };
//
//        // Do final decryption to recover plaintext ECPoint
//        ECPoint decrypted = dec.decrypt(cipherText);
//
//        Assert.assertEquals(plaintext, decrypted);
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
            final XimixNodeContext context = new XimixNodeContext(connectionMaps[nodeNo], new Config(createConfig(nodeName)));

            nodeMap.put(nodeName, context);

            connectionMap.put(nodeName, new ServicesConnection()
            {
                @Override
                public CapabilityMessage[] getCapabilities()
                {
                    return context.getCapabilities();
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

                    Service service = context.getService(message);

                    return service.handle(message);
                }

                @Override
                public void close() throws ServiceConnectionException
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

            Element services = document.createElement("services");
            rootElement.appendChild(services);

            Element service = document.createElement("service");
            services.appendChild(service);

            services.appendChild(createService(document, "org.cryptoworkshop.ximix.crypto.service.NodeKeyRetrievalService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.crypto.service.NodeKeyGenerationService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.crypto.service.NodeSigningService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.crypto.service.NodeDecryptionService"));

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
