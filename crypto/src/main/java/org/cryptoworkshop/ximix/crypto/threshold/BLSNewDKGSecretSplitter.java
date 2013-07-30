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
package org.cryptoworkshop.ximix.crypto.threshold;

import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * A secret splitter based on the New-DKG Algorithm in "Secure Distributed Key Generation" by R. Gennaro, S. Jarecki, H. Krawczyk, and T. Rabin
 */
public class BLSNewDKGSecretSplitter
{
    private final int k;
    private final Element h;
    private final BLS01Parameters domainParams;
    private final ShamirSecretSplitter secretSplitter;
    private final SecureRandom random;

    /**
     * creates an instance over the specified EC domain parameters
     * to share secrets among the specified number of peers
     *
     * @param numberOfPeers the number of peers among which the secret is shared
     * @param threshold number of peers that must be available for secret reconstruction,
     * @param h value to calculate commitment polynomial against.
     * @param domainParams domain parameters for the EC group to use.
     * @param random a source of randomness,
     */
    public BLSNewDKGSecretSplitter(int numberOfPeers, int threshold, BigInteger h, BLS01Parameters domainParams, SecureRandom random)
    {
        if (numberOfPeers < threshold)
        {
            throw new IllegalArgumentException("numberOfPeers must at least be as big as the threshold value.");
        }

        this.k = threshold;
        this.h = domainParams.getG().duplicate().mul(h);
        this.domainParams = domainParams;
        this.secretSplitter = new ShamirSecretSplitter(numberOfPeers, threshold, PairingFactory.getPairing(domainParams.getCurveParameters()).getZr().getOrder(), random);
        this.random = random;
    }

    /**
     * Given the secret generate random coefficients (except for a_0 which is
     * the secret) and compute the function for each privacy peer (who is
     * assigned a dedicated alpha). Coefficients are picked from (0, fieldSize).
     *
     * @param secret the secret to be shared
     * @return the shares of the secret for each privacy peer
     */
    public BLSCommittedSplitSecret split(BigInteger secret)
    {
        // a polynomial
        SplitSecret secretShares = secretSplitter.split(secret);
        // b polynomial
        SplitSecret bShares = secretSplitter.split(getRandomInteger(PairingFactory.getPairing(domainParams.getCurveParameters()).getZr().getOrder(), random));

        Element[] commitments = new Element[k];

        for (int j = 0; j < k; j++)
        {
            commitments[j] = domainParams.getG().mul(secretShares.getCoefficients()[j]).add(h.mul(bShares.getCoefficients()[j]));
        }

        return new BLSCommittedSplitSecret(secretShares.getShares(), secretShares.getCoefficients(), bShares.getShares(), commitments);
    }

    private static BigInteger getRandomInteger(BigInteger n, SecureRandom rand)
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
}
