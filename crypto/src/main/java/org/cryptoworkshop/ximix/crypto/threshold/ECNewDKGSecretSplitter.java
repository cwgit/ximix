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

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * A secret splitter based on the New-DKG Algorithm in "Secure Distributed Key Generation" by R. Gennaro, S. Jarecki, H. Krawczyk, and T. Rabin
 */
public class ECNewDKGSecretSplitter
{
    private final int k;
    private final ECPoint h;
    private final ECDomainParameters domainParams;
    private final ShamirSecretSplitter secretSplitter;

    /**
     * creates an instance over the specified EC domain parameters
     * to share secrets among the specified number of peers
     *
     * @param numberOfPeers the number of peers among which the secret is shared
     * @param threshold number of peers that must be available for secret reconstruction,
     * @param h value to calculate commitment polynomial against.
     * @param domainParams domain parameters for the EC group to use.
     */
    public ECNewDKGSecretSplitter(int numberOfPeers, int threshold, BigInteger h, ECDomainParameters domainParams)
    {
        this.k = threshold;
        this.h = domainParams.getG().multiply(h);
        this.domainParams = domainParams;
        this.secretSplitter = new ShamirSecretSplitter(numberOfPeers, threshold, domainParams.getN());
    }

    /**
     * Given the secret generate random coefficients (except for a_0 which is
     * the secret) and compute the function for each privacy peer (who is
     * assigned a dedicated alpha). Coefficients are picked from (0, fieldSize).
     *
     * @param secret the secret to be shared
     * @param random a source of randomness,
     * @return the shares of the secret for each privacy peer
     */
    public ECCommittedSplitSecret split(BigInteger secret, SecureRandom random)
    {
        // a polynomial
        SplitSecret secretShares = secretSplitter.split(secret, random);
        // b polynomial
        SplitSecret bShares = secretSplitter.split(getRandomInteger(domainParams.getN(), random), random);

        ECPoint[] commitments = new ECPoint[k];

        for (int j = 0; j < k; j++)
        {
            commitments[j] = domainParams.getG().multiply(secretShares.getCoefficients()[j]).add(h.multiply(bShares.getCoefficients()[j]));
        }

        return new ECCommittedSplitSecret(secretShares.getShares(), bShares.getShares(), commitments);
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
