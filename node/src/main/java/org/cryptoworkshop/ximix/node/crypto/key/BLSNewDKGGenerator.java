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

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PrivateKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.cryptoworkshop.ximix.common.asn1.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.crypto.threshold.BLSCommittedSecretShare;
import org.cryptoworkshop.ximix.common.crypto.threshold.BLSCommittedSplitSecret;
import org.cryptoworkshop.ximix.common.crypto.threshold.BLSNewDKGSecretSplitter;
import org.cryptoworkshop.ximix.node.crypto.key.message.BLSCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.service.ThresholdKeyPairGenerator;

/**
 * A New-DKG threshold key pair generator for BLS keys.
 */
public class BLSNewDKGGenerator
    implements ThresholdKeyPairGenerator
{
    private final Algorithm algorithm;
    private final BLSKeyManager keyManager;

    /**
     * Base constructor.
     *
     * @param algorithm the algorithm the BLS keys generated are for.
     * @param keyManager the keyManager to manage the generated key pair.
     */
    public BLSNewDKGGenerator(Algorithm algorithm, BLSKeyManager keyManager)
    {
        this.algorithm = algorithm;
        this.keyManager = keyManager;
    }

    public BLS01Parameters getParameters(String keyID)
    {
        return keyManager.getParams(keyID);
    }

    public BLSCommittedSecretShareMessage[] generateThresholdKey(String keyID, NamedKeyGenParams blsKeyGenParams)
    {
        // TODO: should have a source of randomness.
        AsymmetricCipherKeyPair keyPair = keyManager.generateKeyPair(keyID, algorithm, blsKeyGenParams.getNodesToUse().size(), blsKeyGenParams);

        BLS01PrivateKeyParameters privKey = (BLS01PrivateKeyParameters)keyPair.getPrivate();
        BLSNewDKGSecretSplitter secretSplitter = new BLSNewDKGSecretSplitter(blsKeyGenParams.getNodesToUse().size(), blsKeyGenParams.getThreshold(), blsKeyGenParams.getH(), privKey.getParameters(), new SecureRandom());

        BLSCommittedSplitSecret splitSecret = secretSplitter.split(privKey.getSk().toBigInteger());
        BLSCommittedSecretShare[] shares = splitSecret.getCommittedShares();
        BLSCommittedSecretShareMessage[] messages = new BLSCommittedSecretShareMessage[shares.length];

        BigInteger[] aCoefficients = splitSecret.getCoefficients();
        Element[] qCommitments = new Element[aCoefficients.length];

        for (int i = 0; i != qCommitments.length; i++)
        {
            qCommitments[i] = privKey.getParameters().getG().duplicate().mul(aCoefficients[i]);
        }

        for (int i = 0; i != shares.length; i++)
        {
            messages[i] = new BLSCommittedSecretShareMessage(i, shares[i].getValue(), shares[i].getWitness(), shares[i].getCommitmentFactors(),
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
