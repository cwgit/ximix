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
package org.cryptoworkshop.ximix.node.crypto.key;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.crypto.threshold.ECCommittedSecretShare;
import org.cryptoworkshop.ximix.common.crypto.threshold.ECCommittedSplitSecret;
import org.cryptoworkshop.ximix.common.crypto.threshold.ECNewDKGSecretSplitter;
import org.cryptoworkshop.ximix.node.crypto.key.message.ECCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.crypto.key.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.node.service.ThresholdKeyPairGenerator;

/**
 * A New-DKG threshold key pair generator for Elliptic Curve keys.
 */
public class ECNewDKGGenerator
    implements ThresholdKeyPairGenerator
{
    private final Algorithm algorithm;
    private final ECKeyManager keyManager;

    /**
     * Base constructor.
     *
     * @param algorithm the algorithm the BLS keys generated are for.
     * @param keyManager the keyManager to manage the generated key pair.
     */
    public ECNewDKGGenerator(Algorithm algorithm, ECKeyManager keyManager)
    {
        this.algorithm = algorithm;
        this.keyManager = keyManager;
    }

    public ECDomainParameters getParameters(String keyID)
    {
        return keyManager.getParams(keyID);
    }

    public ECCommittedSecretShareMessage[] generateThresholdKey(String keyID, NamedKeyGenParams ecKeyGenParams)
    {
        // TODO: should have a source of randomness.
        AsymmetricCipherKeyPair keyPair = keyManager.generateKeyPair(keyID, algorithm, ecKeyGenParams.getNodesToUse().size(), ecKeyGenParams);

        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)keyPair.getPrivate();
        ECNewDKGSecretSplitter secretSplitter;

        if (algorithm == Algorithm.ECDSA)
        {
            secretSplitter = new ECNewDKGSecretSplitter(ecKeyGenParams.getNodesToUse().size() * 2, ecKeyGenParams.getThreshold(), ecKeyGenParams.getH(), privKey.getParameters(), new SecureRandom());
        }
        else
        {
            secretSplitter = new ECNewDKGSecretSplitter(ecKeyGenParams.getNodesToUse().size(), ecKeyGenParams.getThreshold(), ecKeyGenParams.getH(), privKey.getParameters(), new SecureRandom());
        }

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
