package org.cryptoworkshop.ximix.node;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.cryptoworkshop.ximix.common.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSecretShare;

class KeyManager
{
    volatile Map<String, AsymmetricCipherKeyPair> keyMap = new HashMap<>();
    volatile Map<String, BigInteger> hMap = new HashMap<>();

    public synchronized boolean hasPrivateKey(String keyID)
    {
        return keyMap.containsKey(keyID) && hMap.containsKey(keyID);
    }

    public synchronized AsymmetricCipherKeyPair generateKeyPair(String keyID, BigInteger h)
    {
        AsymmetricCipherKeyPair kp = keyMap.get(keyID);

        if (kp == null)        // TODO: error? overwrite?
        {
            X9ECParameters params = SECNamedCurves.getByName("secp256r1");

            ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

            kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()), new SecureRandom()));

            kp =  kpGen.generateKeyPair();

            hMap.put(keyID, h);
            keyMap.put(keyID, kp);
        }

        return kp;
    }

    public synchronized AsymmetricCipherKeyPair getKeyPair(String keyID)
    {
        AsymmetricCipherKeyPair kp = keyMap.get(keyID);

        if (kp == null)
        {
            X9ECParameters params = SECNamedCurves.getByName("secp256r1");

            ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

            kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()), new SecureRandom()));

            kp =  kpGen.generateKeyPair();

            keyMap.put(keyID, kp);
        }
        return kp;
    }

    public synchronized SubjectPublicKeyInfo fetchPublicKey(String keyID)
        throws IOException
    {
        AsymmetricCipherKeyPair kp = getKeyPair(keyID);

        if (kp == null)
        {
            return null;
        }
               // TODO: work around for BC 1.49 issues
        return SubjectPublicKeyInfo.getInstance(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()).getEncoded());
    }

    public synchronized void addSharedPrivate(String keyID, ECCommittedSecretShareMessage message)
    {
        X9ECParameters params = SECNamedCurves.getByName("secp256r1");
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());

        ECCommittedSecretShare share = new ECCommittedSecretShare(message.getValue(), message.getWitness(), message.getCommitmentFactors());

        if (share.isRevealed(message.getIndex(), domainParams, hMap.get(keyID)))
        {
            System.err.println("commitment passes!!");
        }
    }
}
