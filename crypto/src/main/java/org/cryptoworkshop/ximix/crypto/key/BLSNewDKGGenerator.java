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
package org.cryptoworkshop.ximix.crypto.key;

import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.service.KeyType;
import org.cryptoworkshop.ximix.common.service.ThresholdKeyPairGenerator;
import org.cryptoworkshop.ximix.crypto.key.message.BLSCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.crypto.key.message.ECKeyGenParams;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSecretShare;
import org.cryptoworkshop.ximix.crypto.threshold.ECCommittedSplitSecret;
import org.cryptoworkshop.ximix.crypto.threshold.ECNewDKGSecretSplitter;

public class BLSNewDKGGenerator
    implements ThresholdKeyPairGenerator
{
    private final KeyType algorithm;
    private final BLSKeyManager keyManager;

    public BLSNewDKGGenerator(KeyType algorithm, BLSKeyManager keyManaged)
    {
        this.algorithm = algorithm;
        keyManager = keyManaged;
    }

    public ECDomainParameters getParameters(String keyID)
    {
        return null; //keyManager.geParams(keyID);
    }

    public BLSCommittedSecretShareMessage[] generateThresholdKey(String keyID, ECKeyGenParams ecKeyGenParams)
    {
        // TODO: should have a source of randomness.
        AsymmetricCipherKeyPair keyPair = keyManager.generateKeyPair(keyID, algorithm, ecKeyGenParams.getNodesToUse().size(), ecKeyGenParams);

        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)keyPair.getPrivate();
        ECNewDKGSecretSplitter secretSplitter = new ECNewDKGSecretSplitter(ecKeyGenParams.getNodesToUse().size(), ecKeyGenParams.getThreshold(), ecKeyGenParams.getH(), privKey.getParameters(), new SecureRandom());

        ECCommittedSplitSecret splitSecret = secretSplitter.split(privKey.getD());
        ECCommittedSecretShare[] shares = splitSecret.getCommittedShares();
        BLSCommittedSecretShareMessage[] messages = new BLSCommittedSecretShareMessage[shares.length];

        BigInteger[] aCoefficients = splitSecret.getCoefficients();
        ECPoint[] qCommitments = new ECPoint[aCoefficients.length];

        for (int i = 0; i != qCommitments.length; i++)
        {
            qCommitments[i] = privKey.getParameters().getG().multiply(aCoefficients[i]);
        }

        for (int i = 0; i != shares.length; i++)
        {
            messages[i] = new BLSCommittedSecretShareMessage(i, shares[i].getValue(), shares[i].getWitness(),
                    ((BLS01PublicKeyParameters)keyPair.getPublic()).getPk());
        }

        return messages;
    }

    public void storeThresholdKeyShare(String keyID, BLSCommittedSecretShareMessage message)
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
