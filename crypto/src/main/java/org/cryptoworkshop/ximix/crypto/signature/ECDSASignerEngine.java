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
import org.cryptoworkshop.ximix.common.message.BigIntegerShareMessage;
import org.cryptoworkshop.ximix.common.message.ECPointShareMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.message.StoreSecretShareMessage;
import org.cryptoworkshop.ximix.common.service.Decoupler;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.PrivateKeyOperator;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.operator.ECPrivateKeyOperator;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSACreateMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAFetchMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAInitialiseMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAPartialCreateMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSAPointMessage;
import org.cryptoworkshop.ximix.crypto.threshold.ShamirSecretSplitter;
import org.cryptoworkshop.ximix.crypto.threshold.SplitSecret;
import org.cryptoworkshop.ximix.crypto.util.BigIntegerShare;
import org.cryptoworkshop.ximix.crypto.util.ECPointShare;
import org.cryptoworkshop.ximix.crypto.util.Share;
import org.cryptoworkshop.ximix.crypto.util.ShareMap;

/**
 * Threshold ECDSA signer based on "A Robust Threshold Elliptic Curve Digital Signature Providing a New Verifiable Secret Sharing Scheme" by Ibrahim, Ali, Ibrahim, and El-sawi.
 * See also "Theory and Practice of Verifiable Secret Sharing" by Rosario Gennaro, Chapter 4.
 */
public class ECDSASignerEngine
    extends SignerEngine
{
    private final ShareMap<SigID, BigInteger> sharedKMap;
    private final ShareMap<SigID, BigInteger> sharedAMap;
    private final ShareMap<SigID, BigInteger> sharedBMap;
    private final ShareMap<SigID, BigInteger> sharedCMap;
    private final ShareMap<SigID, ECPoint> sharedPMap;

    private final Map<String, ECDomainParameters> paramsMap = Collections.synchronizedMap(new HashMap<String, ECDomainParameters>());

    private final Map<SigID, BigInteger> muMap = Collections.synchronizedMap(new HashMap<SigID, BigInteger>());
    private final Map<SigID, BigInteger> rMap = Collections.synchronizedMap(new HashMap<SigID, BigInteger>());

    private final AtomicLong             idCounter = new AtomicLong(1);

    public static enum Type
        implements MessageType
    {
        GENERATE,
        INIT_K_AND_P,
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
        STORE_P,
        FETCH_P
    }

    public ECDSASignerEngine(NodeContext nodeContext)
    {
        super(Algorithms.ECDSA, nodeContext);

        this.sharedKMap = new ShareMap<>(nodeContext.getScheduledExecutor(), nodeContext.getDecoupler(Decoupler.SHARING));
        this.sharedPMap = new ShareMap<>(nodeContext.getScheduledExecutor(), nodeContext.getDecoupler(Decoupler.SHARING));
        this.sharedAMap = new ShareMap<>(nodeContext.getScheduledExecutor(), nodeContext.getDecoupler(Decoupler.SHARING));
        this.sharedBMap = new ShareMap<>(nodeContext.getScheduledExecutor(), nodeContext.getDecoupler(Decoupler.SHARING));
        this.sharedCMap = new ShareMap<>(nodeContext.getScheduledExecutor(), nodeContext.getDecoupler(Decoupler.SHARING));
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
                    sendInitialiseMessage(Type.INIT_A, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_B, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_C, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_R, initialiseMessage);
                    sendInitialiseMessage(Type.INIT_MU, initialiseMessage);

                    r = rMap.get(sigID);

                    s = accumulateBigInteger(nodes, ECDSASignerEngine.Type.PRIVATE_KEY_SIGN, new ECDSAPartialCreateMessage(sigID.getID(), ecdsaCreate.getKeyID(), e, n, ecdsaCreate.getNodesToUse()), n);
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
            case STORE_P:
                StoreSecretShareMessage storeMessage = StoreSecretShareMessage.getInstance(message.getPayload());
                ECDSAPointMessage  pointMessage = ECDSAPointMessage.getInstance(storeMessage.getSecretShareMessage());

                sigID = new SigID(storeMessage.getID());
                domainParams = paramsMap.get(pointMessage.getKeyID());

                sharedPMap.addValue(sigID, new ECPointShare(storeMessage.getSequenceNo(), domainParams.getCurve().decodePoint(pointMessage.getPoint())));

                return new MessageReply(MessageReply.Type.OKAY);
            case FETCH_P:
                ECDSAFetchMessage fetchMessage = ECDSAFetchMessage.getInstance(message.getPayload());
                sigID = new SigID(fetchMessage.getSigID());

                Share<ECPoint> share = sharedPMap.getShare(sigID);

                return replyOkay(new ECPointShareMessage(share.getSequenceNo(), share.getValue()));
            case FETCH_MU:
                fetchMessage = ECDSAFetchMessage.getInstance(message.getPayload());
                sigID = new SigID(fetchMessage.getSigID());

                domainParams = paramsMap.get(fetchMessage.getKeyID());

                Share<BigInteger> kShare = sharedKMap.getShare(sigID);
                return replyOkay(new BigIntegerShareMessage(kShare.getSequenceNo(), kShare.getValue().multiply(
                    sharedAMap.getShare(sigID).getValue()).add(sharedBMap.getShare(sigID).getValue()).mod(domainParams.getN())));
            case PRIVATE_KEY_SIGN:
                ECDSAPartialCreateMessage partialMessage = ECDSAPartialCreateMessage.getInstance(message.getPayload());

                sigID = new SigID(partialMessage.getSigID());

                PrivateKeyOperator operator = nodeContext.getPrivateKeyOperator(partialMessage.getKeyID());

                if (!(operator instanceof ECPrivateKeyOperator))
                {
                    return new MessageReply(MessageReply.Type.ERROR); // TODO
                }

                ECPrivateKeyOperator ecOperator = (ECPrivateKeyOperator)operator;

                Share<BigInteger> aShare = sharedAMap.getShare(sigID);
                BigInteger kInvShare = aShare.getValue().multiply(muMap.get(sigID).modInverse(ecOperator.getDomainParameters().getN()));
                BigInteger eComponent = partialMessage.getE();
                BigInteger dComponent = ecOperator.transform(rMap.get(sigID));

                MessageReply reply = replyOkay(new BigIntegerShareMessage(ecOperator.getSequenceNo(), kInvShare.multiply(eComponent.add(dComponent)).add(sharedCMap.getShare(sigID).getValue())));
                // TODO: need to clean up state tables here.
                return reply;
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

    private void addValue(ShareMap sharedValueTable, SignatureMessage message)
    {
        StoreSecretShareMessage storeMessage = StoreSecretShareMessage.getInstance(message.getPayload());
        SigID sigID = new SigID(storeMessage.getID());

        sharedValueTable.addValue(sigID, new BigIntegerShare(storeMessage.getSequenceNo(), ASN1Integer.getInstance(storeMessage.getSecretShareMessage()).getValue()));
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
        Set<String> nodes = ecdsaCreate.getNodesToUse();

        sharedPMap.waitFor(sigID);        // wait till local P value set

        ECPoint p = accumulateECPoint(nodes, Type.FETCH_P, new ECDSAFetchMessage(ecdsaCreate.getSigID(), ecdsaCreate.getKeyID(), ecdsaCreate.getNodesToUse()), domainParams.getCurve(), domainParams.getN());
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

        muMap.put(sigID, accumulateBigInteger(ecdsaCreate.getNodesToUse(), Type.FETCH_MU, new ECDSAFetchMessage(ecdsaCreate.getSigID(), ecdsaCreate.getKeyID(), ecdsaCreate.getNodesToUse()), n));
    }

    private void generateAndSendZeroShare(SignatureMessage message, Type type, ShareMap shareMap)
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
        private final ShareMap sharedValueMap;
        private final BigInteger[] messages;

        SendShareTask(SigID sigID, Type type, Set<String> peers, ShareMap sharedValueMap, BigInteger[] messages)
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
                    sharedValueMap.addValue(sigID, new BigIntegerShare(index, messages[index]));
                }
                else
                {
                    final int counter = index;
                    execute(new Runnable()
                    {
                        public void run()
                        {
                            try
                            {
                                MessageReply rep = sendMessage(name, type, new StoreSecretShareMessage(sigID.getID(), counter, new ASN1Integer(messages[counter])));
                            }
                            catch (ServiceConnectionException e)
                            {
                                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                            }
                        }
                    });

                }
                index++;
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
                    sharedPMap.addValue(sigID, new ECPointShare(counter, p));
                }
                else
                {
                    schedule(new Runnable()
                    {
                        public void run()
                        {
                            try
                            {
                                MessageReply rep = sendMessage(name, Type.STORE_P, new StoreSecretShareMessage(sigID.getID(), counter, new ECDSAPointMessage(keyID, p)));
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
