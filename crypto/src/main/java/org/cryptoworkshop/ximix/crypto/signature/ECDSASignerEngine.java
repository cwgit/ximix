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
package org.cryptoworkshop.ximix.crypto.signature;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.message.ECPointMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.message.StoreSecretShareMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSACreateMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAFetchMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAInitialiseMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAPartialCreateMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAPointMessage;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.crypto.threshold.ShamirSecretSplitter;
import org.cryptoworkshop.ximix.crypto.threshold.SplitSecret;
import org.cryptoworkshop.ximix.crypto.util.SharedBigIntegerMap;
import org.cryptoworkshop.ximix.crypto.util.SharedECPointMap;

/**
 * Threshold ECDSA signer based on "A Robust Threshold Elliptic Curve Digital Signature Providing a New Verifiable Secret Sharing Scheme" by Ibrahim, Ali, Ibrahim, and El-sawi.
 * See also "Theory and Practice of Verifiable Secret Sharing" by Rosario Gennaro, Chapter 4.
 */
public class ECDSASignerEngine
    extends SignerEngine
{
    private final SharedBigIntegerMap<SigID> sharedKMap;
    private final SharedBigIntegerMap<SigID> sharedAMap;
    private final SharedBigIntegerMap<SigID> sharedBMap;
    private final SharedBigIntegerMap<SigID> sharedCMap;
    private final SharedBigIntegerMap<SigID> sharedMuMap;
    private final SharedECPointMap<SigID> sharedPMap;

    private final Map<String, ECDomainParameters> paramsMap = Collections.synchronizedMap(new HashMap<String, ECDomainParameters>());

    private final Map<SigID, BigInteger> muMap = Collections.synchronizedMap(new HashMap<SigID, BigInteger>());
    private final Map<SigID, BigInteger> rMap = Collections.synchronizedMap(new HashMap<SigID, BigInteger>());

    private final AtomicLong             idCounter = new AtomicLong(1);

    public static enum Type
        implements MessageType
    {
        GENERATE,
        INIT_K_AND_P,
        INIT_P,
        INIT_A,
        INIT_B,
        INIT_C,
        INIT_R,
        INIT_MU,
        FETCH_MU,
        PRIVATE_KEY_SIGN,
        STORE_K,
        STORE_A,
        STORE_B,
        STORE_C,
        STORE_MU,
        STORE_P,
        FETCH_P
    }

    public ECDSASignerEngine(NodeContext nodeContext)
    {
        super(Algorithms.ECDSA, nodeContext);

        this.sharedKMap = new SharedBigIntegerMap<>(nodeContext.getScheduledExecutor());
        this.sharedPMap = new SharedECPointMap<>(nodeContext.getScheduledExecutor());
        this.sharedAMap = new SharedBigIntegerMap<>(nodeContext.getScheduledExecutor());
        this.sharedBMap = new SharedBigIntegerMap<>(nodeContext.getScheduledExecutor());
        this.sharedCMap = new SharedBigIntegerMap<>(nodeContext.getScheduledExecutor());
        this.sharedMuMap = new SharedBigIntegerMap<>(nodeContext.getScheduledExecutor());
    }

    public int getAlgorithm()
    {
        return Algorithms.ECDSA;
    }

    public MessageReply handle(final SignatureMessage message)
    {
        try
        {
            switch ((Type)message.getType())
            {
            case GENERATE:
                final ECDSACreateMessage ecdsaCreate = ECDSACreateMessage.getInstance(message.getPayload());
                final Set<String> nodes = ecdsaCreate.getNodesToUse();

                SigID sigID = new SigID(nodeContext.getName() + ".ECDSA." + idCounter.getAndIncrement());

                SubjectPublicKeyInfo pubKeyInfo = nodeContext.getPublicKey(ecdsaCreate.getKeyID());
                ECDomainParameters domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo)).getParameters();
                BigInteger n = domainParams.getN();
                BigInteger e = calculateE(n, ecdsaCreate.getMessage());
                // TODO: need to take into account node failure during startup.
                BigInteger r, s;
                do // generate s
                {
                    ECDSAInitialiseMessage initialiseMessage = new ECDSAInitialiseMessage(sigID.getID(), ecdsaCreate.getKeyID(), ecdsaCreate.getThreshold(), domainParams.getN(), ecdsaCreate.getNodesToUse());

                    sendInitialiseMessage(Type.INIT_K_AND_P, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_P, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_A, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_B, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_C, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_R, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_MU, initialiseMessage);

                    r = rMap.get(sigID);

                    s = accumulateBigInt(nodes, ECDSASignerEngine.Type.PRIVATE_KEY_SIGN, new ECDSAPartialCreateMessage(sigID.getID(), ecdsaCreate.getKeyID(), e, n, ecdsaCreate.getNodesToUse()), n);
                }
                while (s.equals(BigInteger.ZERO));

                ASN1EncodableVector v = new ASN1EncodableVector();

                v.add(new ASN1Integer(r));
                v.add(new ASN1Integer(s));

                return new MessageReply(MessageReply.Type.OKAY, new DERSequence(v));
            case INIT_K_AND_P:
                generateAndSendKAndP(message);

                return new MessageReply(MessageReply.Type.OKAY);
            case INIT_A:
                generateAndSendA(message);

                return new MessageReply(MessageReply.Type.OKAY);
            case INIT_B:
                generateAndSendZeroShare(message, Type.STORE_B, sharedBMap);

                return new MessageReply(MessageReply.Type.OKAY);
            case INIT_C:
                generateAndSendZeroShare(message, Type.STORE_C, sharedCMap);

                return new MessageReply(MessageReply.Type.OKAY);
            case INIT_R:
                initialiseR(message);

                return new MessageReply(MessageReply.Type.OKAY);
            case INIT_MU:
                initialiseMu(message);

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE_K:
                addValue(sharedKMap, message);

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE_A:
                addValue(sharedAMap, message);

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE_B:
                addValue(sharedBMap, message);

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE_C:
                addValue(sharedCMap, message);

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE_MU:
                addValue(sharedMuMap, message);

                return new MessageReply(MessageReply.Type.OKAY);
            case STORE_P:
                StoreSecretShareMessage storeMessage = StoreSecretShareMessage.getInstance(message.getPayload());
                ECDSAPointMessage  pointMessage = ECDSAPointMessage.getInstance(storeMessage.getSecretShareMessage());

                sigID = new SigID(storeMessage.getID());
                domainParams = paramsMap.get(pointMessage.getKeyID());

                sharedPMap.addValue(sigID, domainParams.getCurve().decodePoint(pointMessage.getPoint()));

                return new MessageReply(MessageReply.Type.OKAY);
            case FETCH_P:
                ECDSAFetchMessage fetchMessage = ECDSAFetchMessage.getInstance(message.getPayload());
                sigID = new SigID(fetchMessage.getSigID());

                return replyOkay(new ECPointMessage(sharedPMap.getValue(sigID)));
            case FETCH_MU:
                fetchMessage = ECDSAFetchMessage.getInstance(message.getPayload());
                sigID = new SigID(fetchMessage.getSigID());

                domainParams = paramsMap.get(fetchMessage.getKeyID());

                return replyOkay(new BigIntegerMessage(sharedKMap.getValue(sigID).multiply(sharedAMap.getValue(sigID)).add(sharedBMap.getValue(sigID)).mod(domainParams.getN())));
            case PRIVATE_KEY_SIGN:
                ECDSAPartialCreateMessage partialMessage = ECDSAPartialCreateMessage.getInstance(message.getPayload());

                sigID = new SigID(partialMessage.getSigID());
                domainParams = paramsMap.get(partialMessage.getKeyID());

                BigInteger kInvShare = sharedAMap.getValue(sigID).multiply(muMap.get(sigID).modInverse(domainParams.getN()));
                BigInteger eComponent = partialMessage.getE();
                BigInteger dComponent = nodeContext.performPartialSign(partialMessage.getKeyID(), rMap.get(sigID));

                return replyOkay(new BigIntegerMessage(kInvShare.multiply(eComponent.add(dComponent)).add(sharedCMap.getValue(sigID))));
            default:
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeSigningService."));
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("NodeKeyGenerationService failure: " + e.getMessage()));
        }
    }

    private void sendInitialiseMessage(Type initType, ECDSAInitialiseMessage createMessage)
    {
        Set<String> nodes = createMessage.getNodesToUse();

        for (String nodeName : nodes)
        {
            try
            {
                sendMessage(nodeName, initType, createMessage);
            }
            catch (ServiceConnectionException e)
            {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }
    }

    private void addValue(SharedBigIntegerMap sharedValueTable, SignatureMessage message)
    {
        StoreSecretShareMessage storeMessage = StoreSecretShareMessage.getInstance(message.getPayload());
        SigID sigID = new SigID(storeMessage.getID());

        sharedValueTable.addValue(sigID, ASN1Integer.getInstance(storeMessage.getSecretShareMessage()).getValue());
    }

    private void generateAndSendKAndP(SignatureMessage message)
        throws IOException
    {
        ECDSAInitialiseMessage ecdsaCreate = ECDSAInitialiseMessage.getInstance(message.getPayload());
        SubjectPublicKeyInfo pubKeyInfo = nodeContext.getPublicKey(ecdsaCreate.getKeyID());
        ECDomainParameters domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo)).getParameters();
        SigID sigID = new SigID(ecdsaCreate.getSigID());

        sharedKMap.init(sigID, ecdsaCreate.getNodesToUse().size());

        paramsMap.put(ecdsaCreate.getKeyID(), domainParams);

        BigInteger n = ecdsaCreate.getN();
        int nBitLength = n.bitLength();
        BigInteger k, r;

        do // generate r
        {
            do
            {
                k = new BigInteger(nBitLength, new SecureRandom());
            }
            while (k.equals(BigInteger.ZERO) || k.compareTo(n) >= 0);

            ECPoint p = domainParams.getG().multiply(k);

            // 5.3.3
            BigInteger x = p.getX().toBigInteger();

            r = x.mod(n);
        }
        while (r.equals(BigInteger.ZERO));

        ShamirSecretSplitter sss = new ShamirSecretSplitter(ecdsaCreate.getNodesToUse().size(), ecdsaCreate.getThreshold(), n, new SecureRandom());

        SplitSecret split = sss.split(k);

        execute(new SendShareTask(sigID, Type.STORE_K, ecdsaCreate.getNodesToUse(), sharedKMap, split.getShares()));

        sharedPMap.init(sigID, ecdsaCreate.getNodesToUse().size());

        execute(new SendPointShareTask(sigID, ecdsaCreate.getKeyID(), ecdsaCreate.getNodesToUse(), split.getShares()));
    }

    private void generateAndSendA(SignatureMessage message)
        throws IOException
    {
        ECDSAInitialiseMessage ecdsaCreate = ECDSAInitialiseMessage.getInstance(message.getPayload());
        BigInteger n = ecdsaCreate.getN();
        int nBitLength = n.bitLength();
        BigInteger a;

        SigID sigID = new SigID(ecdsaCreate.getSigID());
        sharedAMap.init(sigID, ecdsaCreate.getNodesToUse().size());

        do
        {
            a = new BigInteger(nBitLength, new SecureRandom());
        }
        while (a.equals(BigInteger.ZERO) || a.compareTo(n) >= 0);

        ShamirSecretSplitter sss = new ShamirSecretSplitter(ecdsaCreate.getNodesToUse().size(), ecdsaCreate.getThreshold(), n, new SecureRandom());

        SplitSecret split = sss.split(a);

        execute(new SendShareTask(sigID, Type.STORE_A, ecdsaCreate.getNodesToUse(), sharedAMap, split.getShares()));
    }

    private void initialiseR(SignatureMessage message)
        throws IOException, ServiceConnectionException
    {
        ECDSAInitialiseMessage ecdsaCreate = ECDSAInitialiseMessage.getInstance(message.getPayload());
        SigID sigID = new SigID(ecdsaCreate.getSigID());
        ECDomainParameters domainParams = paramsMap.get(ecdsaCreate.getKeyID());
        int counter = 0;
        Set<String> nodes = ecdsaCreate.getNodesToUse();
        MessageReply[] replys = new MessageReply[nodes.size()];

        sharedPMap.waitFor(sigID);        // wait till local P value set

        for (String nodeName : nodes)
        {
            replys[counter++] = sendMessage(nodeName, Type.FETCH_P, new ECDSAFetchMessage(ecdsaCreate.getSigID(), ecdsaCreate.getKeyID(), ecdsaCreate.getNodesToUse()));
        }

        ECPoint[] pVals = new ECPoint[replys.length];

        for (int i = 0; i != replys.length; i++)
        {
            if (replys[i] == null || replys[i].getType() != MessageReply.Type.OKAY)
            {
                pVals[i] = null;
            }
            else
            {
                pVals[i] = ECPointMessage.getInstance(domainParams.getCurve(), replys[i].getPayload()).getPoint();
            }
        }

        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(ecdsaCreate.getThreshold(), domainParams.getN());
        BigInteger[] weights = calculator.computeWeights(pVals);

        ECPoint p = pVals[0].multiply(weights[0]);
        for (int i = 1; i < weights.length; i++)
        {
            if (pVals[i] != null)
            {
                p = p.add(pVals[i].multiply(weights[i]));
            }
        }

        // 5.3.3
        BigInteger x = p.getX().toBigInteger();
        BigInteger r = x.mod(domainParams.getN());

        rMap.put(sigID, r);
    }

    private void initialiseMu(SignatureMessage message)
        throws IOException, ServiceConnectionException
    {
        ECDSAInitialiseMessage ecdsaCreate = ECDSAInitialiseMessage.getInstance(message.getPayload());
        SigID sigID = new SigID(ecdsaCreate.getSigID());
        BigInteger n = ecdsaCreate.getN();

        muMap.put(sigID, accumulateBigInt(ecdsaCreate.getNodesToUse(), Type.FETCH_MU, new ECDSAFetchMessage(ecdsaCreate.getSigID(), ecdsaCreate.getKeyID(), ecdsaCreate.getNodesToUse()), n));
    }

    private void generateAndSendZeroShare(SignatureMessage message, Type type, SharedBigIntegerMap shareMap)
        throws IOException
    {
        ECDSAInitialiseMessage ecdsaCreate = ECDSAInitialiseMessage.getInstance(message.getPayload());
        SigID sigID = new SigID(ecdsaCreate.getSigID());
        BigInteger n = ecdsaCreate.getN();

        shareMap.init(sigID, ecdsaCreate.getNodesToUse().size());

        ShamirSecretSplitter sss = new ShamirSecretSplitter(ecdsaCreate.getNodesToUse().size(), ecdsaCreate.getThreshold() * 2, n, new SecureRandom());

        SplitSecret split = sss.split(BigInteger.ZERO);

        execute(new SendShareTask(sigID, type, ecdsaCreate.getNodesToUse(), shareMap, split.getShares()));
    }

    private BigInteger calculateE(BigInteger n, byte[] message)
    {
        int log2n = n.bitLength();
        int messageBitLength = message.length * 8;

        if (log2n >= messageBitLength)
        {
            return new BigInteger(1, message);
        }
        else
        {
            BigInteger trunc = new BigInteger(1, message);

            trunc = trunc.shiftRight(messageBitLength - log2n);

            return trunc;
        }
    }

    private class SigID
    {
        private final String id;

        public SigID(String id)
        {
            this.id = id;
        }

        public String getID()
        {
            return id;
        }

        public int hashCode()
        {
            return id.hashCode();
        }

        public boolean equals(Object o)
        {
            if (o == this)
            {
                return true;
            }

            if (o instanceof SigID)
            {
                SigID other = (SigID)o;

                return this.id.equals(other.id);
            }

            return false;
        }
    }

    private class SendShareTask
        implements Runnable
    {
        private final Type type;
        private final SigID sigID;
        private final Set<String> peers;
        private final SharedBigIntegerMap sharedValueMap;
        private final BigInteger[] messages;

        SendShareTask(SigID sigID, Type type, Set<String> peers, SharedBigIntegerMap sharedValueMap, BigInteger[] messages)
        {
            this.sigID = sigID;
            this.type = type;
            this.peers = peers;
            this.sharedValueMap = sharedValueMap;
            this.messages = messages;
        }

        public void run()
        {
            int index = 0;
            for (final String name : peers)
            {
                System.err.println("sending k: " + nodeContext.getName() + " to " + name);
                if (name.equals(nodeContext.getName()))
                {
                    sharedValueMap.addValue(sigID, messages[index++]);
                }
                else
                {
                    final int counter = index++;
                    execute(new Runnable()
                    {
                        public void run()
                        {
                            try
                            {
                                MessageReply rep = sendMessage(name, type, new StoreSecretShareMessage(sigID.getID(), new ASN1Integer(messages[counter])));
                            }
                            catch (ServiceConnectionException e)
                            {
                                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                            }
                        }
                    });

                }
            }
        }
    }

    private class SendPointShareTask
        implements Runnable
    {
        private final SigID sigID;
        private final String keyID;
        private final Set<String> peers;
        private final BigInteger[] messages;

        SendPointShareTask(SigID sigID, String keyID, Set<String> peers, BigInteger[] messages)
        {
            this.sigID = sigID;
            this.keyID = keyID;
            this.peers = peers;
            this.messages = messages;
        }

        public void run()
        {
            ECDomainParameters domainParams = paramsMap.get(keyID);

            int index = 0;
            for (final String name : peers)
            {
                final int counter = index++;

                final ECPoint p = domainParams.getG().multiply(messages[counter]);

                if (name.equals(nodeContext.getName()))
                {
                    sharedPMap.addValue(sigID, p);
                }
                else
                {
                    schedule(new Runnable()
                    {
                        public void run()
                        {
                            try
                            {
                                MessageReply rep = sendMessage(name, Type.STORE_P, new StoreSecretShareMessage(sigID.getID(), new ECDSAPointMessage(keyID, p)));
                            }
                            catch (ServiceConnectionException e)
                            {
                                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                            }
                        }
                    }, 1000, TimeUnit.MILLISECONDS);
                }
            }
        }
    }
}
