package org.cryptoworkshop.ximix.node;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.common.message.ECKeyGenParams;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSecretShare;

class KeyManager
{
    private static final int TIME_OUT = 20;

    private final Map<String, AsymmetricCipherKeyPair> keyMap = new HashMap<>();
    private final Map<String, BigInteger> hMap = new HashMap<>();
    private final Map<String, CountDownLatch> latchMap = new HashMap<>();
    private final Map<String, BigInteger> sharedPrivateKeyMap = new HashMap<>();
    private final Map<String, ECPoint> sharedPublicKeyMap = new HashMap<>();

    public synchronized boolean hasPrivateKey(String keyID)
    {
        return keyMap.containsKey(keyID);
    }

    public synchronized AsymmetricCipherKeyPair generateKeyPair(String keyID, String n, int numberOfPeers, ECKeyGenParams keyGenParams)
    {
        AsymmetricCipherKeyPair kp = keyMap.get(keyID);

        if (kp == null)        // TODO: error? overwrite?
        {
            X9ECParameters params = ECNamedCurveTable.getByName(keyGenParams.getDomainParameters());

            ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

            kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()), new SecureRandom()));

            kp =  kpGen.generateKeyPair();

            latchMap.put(keyID, new CountDownLatch(numberOfPeers));
            hMap.put(keyID, keyGenParams.getH());
            keyMap.put(keyID, kp);
        }
        else
        {
            System.err.println("duplicate key request!!!");
        }

        return kp;
    }

    public SubjectPublicKeyInfo fetchPublicKey(String keyID)
        throws IOException
    {
        boolean partialKey;

        synchronized (this)
        {
           partialKey = latchMap.containsKey(keyID);
        }

        if (partialKey)
        {
            try
            {
                if (latchMap.get(keyID).await(TIME_OUT, TimeUnit.SECONDS))
                {
                    synchronized (this)
                    {
                        ECPoint q = sharedPublicKeyMap.get(keyID);
                        ECDomainParameters params = ((ECPublicKeyParameters)keyMap.get(keyID).getPublic()).getParameters();

                        return SubjectPublicKeyInfo.getInstance(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new ECPublicKeyParameters(q,params)).getEncoded());
                    }
                }
                else
                {
                    System.err.println("timeout!!!");
                    // TODO: log timeout
                    return null;
                }
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }

        return null;
    }

    public synchronized void buildSharedKey(String keyID, ECCommittedSecretShareMessage message)
    {
        ECDomainParameters domainParams = ((ECPublicKeyParameters)keyMap.get(keyID).getPublic()).getParameters();
        ECCommittedSecretShare share = new ECCommittedSecretShare(message.getValue(), message.getWitness(), message.getCommitmentFactors());

        if (share.isRevealed(message.getIndex(), domainParams, hMap.get(keyID)))
        {
            BigInteger myD = sharedPrivateKeyMap.get(keyID);

            if (myD != null)
            {
                sharedPrivateKeyMap.put(keyID, myD.add(message.getValue()));
            }
            else
            {
                sharedPrivateKeyMap.put(keyID, message.getValue());
            }

            ECPoint jointPubKey = sharedPublicKeyMap.get(keyID);

            if (jointPubKey != null)
            {
                sharedPublicKeyMap.put(keyID, jointPubKey.add(message.getQ()));
            }
            else
            {
                sharedPublicKeyMap.put(keyID, message.getQ());
            }

            latchMap.get(keyID).countDown();
        }
        else
        {
            System.err.println("commitment fails!!");

            // TODO: need a policy decision on this one!!!
        }
    }

    public BigInteger getPartialPrivateKey(String keyID)
    {
        try
        {
            if (latchMap.get(keyID).await(TIME_OUT, TimeUnit.SECONDS))
            {
                return sharedPrivateKeyMap.get(keyID);
            }
            else
            {
                // TODO: log timeout.
                return null;
            }
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
            // TODO: log
            return null;
        }
    }
}
