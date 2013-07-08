package org.cryptoworkshop.ximix.crypto.key;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.service.ThresholdKeyPairGenerator;
import org.cryptoworkshop.ximix.crypto.KeyType;
import org.cryptoworkshop.ximix.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.crypto.key.message.ECKeyGenParams;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSecretShare;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSplitSecret;
import org.cryptoworkshop.ximix.crypto.threshold.ECNewDKGSecretSplitter;

public class ECNewDKGGenerator
    implements ThresholdKeyPairGenerator
{
    private final KeyType algorithm;
    private final KeyManager keyManager;

    public ECNewDKGGenerator(KeyType algorithm, KeyManager keyManaged)
    {
        this.algorithm = algorithm;
        keyManager = keyManaged;
    }

    public ECCommittedSecretShareMessage[] generateThresholdKey(String keyID, ECKeyGenParams ecKeyGenParams)
    {
        // TODO: should have a source of randomness.
        AsymmetricCipherKeyPair keyPair = keyManager.generateKeyPair(keyID, ecKeyGenParams.getNodesToUse().size(), ecKeyGenParams);

        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECNewDKGSecretSplitter secretSplitter = new ECNewDKGSecretSplitter(ecKeyGenParams.getNodesToUse().size(), ecKeyGenParams.getThreshold(), ecKeyGenParams.getH(), privKey.getParameters(), new SecureRandom());

        ECCommittedSplitSecret splitSecret = secretSplitter.split(privKey.getD());
        ECCommittedSecretShare[] shares = splitSecret.getCommittedShares();
        ECCommittedSecretShareMessage[] messages = new ECCommittedSecretShareMessage[shares.length];

        BigInteger[] aCoefficients = splitSecret.getCoefficients();
        ECPoint[] qCommitments = new ECPoint[aCoefficients.length];

        for (int i = 0; i != qCommitments.length; i++)
        {
            qCommitments[i] = privKey.getParameters().getG().multiply(aCoefficients[i]);
        }

        for (int i = 0; i != shares.length; i++)
        {
            messages[i] = new ECCommittedSecretShareMessage(i, shares[i].getValue(), shares[i].getWitness(), shares[i].getCommitmentFactors(),
                    ((ECPublicKeyParameters) keyPair.getPublic()).getQ(), qCommitments);
        }

        return messages;
    }

    public void storeThresholdKeyShare(String keyID, ECCommittedSecretShareMessage message)
    {
        try
        {
            keyManager.buildSharedKey(keyID, message);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
