package org.cryptoworkshop.ximix.node.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

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
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.GenerateKeyPairMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSecretShare;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;
import org.junit.Assert;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.node.XimixNodeContext;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class KeyGenerationTest
{
    @Test
    public void testBasicGenerationNoPeers()
        throws Exception
    {
        XimixNodeContext context = new XimixNodeContext(new HashMap<String, ServicesConnection>(), new Config(createConfig("A")));

        try
        {
            Set<String> peers = new HashSet(Arrays.asList("A", "B", "C"));
            ECCommittedSecretShareMessage[] messages = context.generateThresholdKey("EC_KEY", peers, 4, BigInteger.valueOf(1000001));

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

        BigInteger h = BigInteger.valueOf(1000001);
        Set<String> peers = new HashSet(Arrays.asList("A", "B", "C", "D", "E"));
        ECCommittedSecretShareMessage[] messages = context.generateThresholdKey("EC_KEY", peers, 4, h);

        Assert.assertEquals(5, messages.length);

        X9ECParameters params = SECNamedCurves.getByName("secp256r1"); // TODO: should be on the context!!
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());

        for (int i = 0; i != messages.length; i++)
        {
            ECCommittedSecretShareMessage message = ECCommittedSecretShareMessage.getInstance(params.getCurve(), messages[i].getEncoded());
            ECCommittedSecretShare share = new ECCommittedSecretShare(message.getValue(), message.getWitness(), message.getCommitmentFactors());

            Assert.assertTrue(share.isRevealed(i, domainParams, h));
        }
    }

    @Test
    public void testGenerationViaMessage()
        throws Exception
    {
        final Map<String, XimixNodeContext>  contextMap = createContextMap(5);

        XimixNodeContext context = contextMap.get("A");

        BigInteger h = BigInteger.valueOf(1000001);

        ServicesConnection connection = context.getPeerMap().get("B");

        final Set<String> peers = new HashSet(Arrays.asList("A", "B", "C", "D", "E"));
        final GenerateKeyPairMessage genKeyPairMessage = new GenerateKeyPairMessage("ECKEY", peers, 4, h);
        MessageReply reply = connection.sendMessage(CommandMessage.Type.INITIATE_GENERATE_KEY_PAIR, genKeyPairMessage);

        // TODO: we need an "all clear" to show the key has settled
        Thread.sleep(5000L);

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
        ECPoint plaintext = generatePoint(context.<ECDomainParameters>getDomainParameters("ECKEY"), new SecureRandom());

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

                for (String nodeName : genKeyPairMessage.getNodesToUse())
                {
                    XimixNodeContext context = contextMap.get(nodeName);

                    partialDecs[index++] = context.getPartialDecrypt("ECKEY", cipherText.getX());
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
                public Capability[] getCapabilities()
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

                    Service service = context.getService(message.getType());

                    return service.handle(message);
                }

                @Override
                public MessageReply sendThresholdMessage(MessageType type, int minimumNumberOfPeers, ASN1Encodable messagePayload)
                    throws ServiceConnectionException
                {
                    for (String nodeName : connectionMaps[nodeNo].keySet())
                    {
                        Message message = Message.getInstance(messagePayload);

                        Service service = context.getService(message.getType());

                        service.handle(message);
                    }

                    return null;
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

                connectionMaps[i].put(node, connectionMap.get(node));
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

            Element portNo = document.createElement("name");

            rootElement.appendChild(portNo);
            portNo.appendChild(document.createTextNode(nodeName));

            Element services = document.createElement("services");
            rootElement.appendChild(services);

            Element service = document.createElement("service");
            services.appendChild(service);

            services.appendChild(createService(document, "org.cryptoworkshop.ximix.crypto.service.NodeKeyRetrievalService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.crypto.service.NodeKeyGenerationService"));
            services.appendChild(createService(document, "org.cryptoworkshop.ximix.crypto.service.NodeSigningService"));

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
