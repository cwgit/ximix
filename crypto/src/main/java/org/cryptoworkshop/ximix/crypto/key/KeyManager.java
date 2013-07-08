package org.cryptoworkshop.ximix.crypto.key;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
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
import org.cryptoworkshop.ximix.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.crypto.key.message.ECKeyGenParams;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSecretShare;
import org.cryptoworkshop.ximix.crypto.util.SharedBigIntegerMap;
import org.cryptoworkshop.ximix.crypto.util.SharedECPointMap;

public class KeyManager
{
    private static final int TIME_OUT = 20;

    private final Map<String, AsymmetricCipherKeyPair> keyMap = new HashMap<>();
    private final Map<String, BigInteger> hMap = new HashMap<>();
    private final SharedBigIntegerMap sharedPrivateKeyMap;
    private final SharedECPointMap sharedPublicKeyMap;

    public KeyManager(ScheduledExecutorService executor)
    {
        sharedPublicKeyMap = new SharedECPointMap(executor);
        sharedPrivateKeyMap = new SharedBigIntegerMap(executor);
    }

    public synchronized boolean hasPrivateKey(String keyID)
    {
        return keyMap.containsKey(keyID);
    }

    public synchronized AsymmetricCipherKeyPair generateKeyPair(String keyID, int numberOfPeers, ECKeyGenParams keyGenParams)
    {
        AsymmetricCipherKeyPair kp = keyMap.get(keyID);

        if (kp == null)
        {
            X9ECParameters params = ECNamedCurveTable.getByName(keyGenParams.getDomainParameters());

            ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

            kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()), new SecureRandom()));

            kp =  kpGen.generateKeyPair();

            sharedPrivateKeyMap.init(keyID, numberOfPeers);
            sharedPublicKeyMap.init(keyID, numberOfPeers);

            hMap.put(keyID, keyGenParams.getH());
            keyMap.put(keyID, kp);
        }
        else
        {
            throw new IllegalStateException("key " + keyID + " already exists.");
        }

        return kp;
    }

    public SubjectPublicKeyInfo fetchPublicKey(String keyID)
        throws IOException
    {
        if (sharedPublicKeyMap.containsKey(keyID))
        {
            ECPoint q = sharedPublicKeyMap.getValue(keyID, TIME_OUT, TimeUnit.SECONDS);
            ECDomainParameters params = ((ECPublicKeyParameters)keyMap.get(keyID).getPublic()).getParameters();

            return SubjectPublicKeyInfo.getInstance(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new ECPublicKeyParameters(q, params)).getEncoded());
        }

        return null;
    }

    public synchronized void buildSharedKey(String keyID, ECCommittedSecretShareMessage message)
    {
        ECDomainParameters domainParams = ((ECPublicKeyParameters)keyMap.get(keyID).getPublic()).getParameters();
        ECCommittedSecretShare share = new ECCommittedSecretShare(message.getValue(), message.getWitness(), message.getCommitmentFactors());

        if (share.isRevealed(message.getIndex(), domainParams, hMap.get(keyID)))
        {
            sharedPrivateKeyMap.addValue(keyID, message.getValue());
            sharedPublicKeyMap.addValue(keyID, message.getQ());
        }
        else
        {
            System.err.println("commitment fails!!");

            // TODO: need a policy decision on this one!!!
        }
    }

    public BigInteger getPartialPrivateKey(String keyID)
    {
        return sharedPrivateKeyMap.getValue(keyID);
    }
}
