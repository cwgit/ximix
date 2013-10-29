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
package org.cryptoworkshop.ximix.common.crypto.threshold;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A secret splitter based on Shamir's method.
 */
public class ShamirSecretSplitter
{
    private final int numberOfPeers;
    private final int k;
    private final BigInteger fieldSize;
    private final SecureRandom random;
    private final BigInteger[] alphas;
    private final BigInteger[][] alphasPow;

    /**
     * creates a ShamirSecretSplitter instance over the specified field
     * to share secrets among the specified number of peers
     *
     * @param numberOfPeers the number of peers among which the secret is shared
     * @param threshold number of peers that must be available for secret reconstruction,
     * @param fieldSize size of the group's field.
     * @param random a source of randomness,
     */
    public ShamirSecretSplitter(int numberOfPeers, int threshold, BigInteger fieldSize, SecureRandom random)
    {
        this.numberOfPeers = numberOfPeers;
        this.k = threshold;
        this.fieldSize = fieldSize;
        this.random = random;

         // Pre-calculate powers for each peer.
        alphas = new BigInteger[numberOfPeers];
        alphasPow = new BigInteger[numberOfPeers][k];

        if (k > 1)
        {
            for (int i = 0; i < numberOfPeers; i++)
            {
                alphas[i] = alphasPow[i][1] = BigInteger.valueOf(i + 1);
                for (int degree = 2; degree < k; degree++)
                {
                    alphasPow[i][degree] = alphasPow[i][degree - 1].multiply(alphas[i]);
                }
            }
        }
        else
        {
            for (int i = 0; i < numberOfPeers; i++)
            {
                alphas[i] = BigInteger.valueOf(i + 1);
            }
        }
    }

    /**
     * Given the secret generate random coefficients (except for a<sub>0</sub> which is
     * the secret) and compute the function for each privacy peer (who is
     * assigned a dedicated alpha). Coefficients are picked from (0, fieldSize).
     *
     * @param secret the secret to be shared
     * @return the shares of the secret for each privacy peer
     */
    public SplitSecret split(BigInteger secret)
    {
        BigInteger[] shares = new BigInteger[numberOfPeers];
        BigInteger[] coefficients = new BigInteger[k];

        // D0 for each share
        for (int privacyPeerIndex = 0; privacyPeerIndex < numberOfPeers; privacyPeerIndex++)
        {
            shares[privacyPeerIndex] = secret;
        }

        coefficients[0] = secret;

        // D1 to DT for each share
        for (int degree = 1; degree < k; degree++)
        {
            BigInteger nextCoefficient = generateCoeff(fieldSize, random);

            coefficients[degree] = nextCoefficient;

            for (int privacyPeerIndex = 0; privacyPeerIndex < numberOfPeers; privacyPeerIndex++)
            {
                shares[privacyPeerIndex] = shares[privacyPeerIndex].add(
                    nextCoefficient.multiply(alphasPow[privacyPeerIndex][degree]).mod(fieldSize)).mod(fieldSize);
            }
        }

        return new SplitSecret(shares, coefficients);
    }

    // Shamir's original paper actually gives from [0, fieldSize) as the range in
    // which coefficients can be chosen, this isn't true for the highest order term
    // as it would have the effect of reducing the order of the polynomial. We guard
    // against this by using (0, fieldSize).
    private static BigInteger generateCoeff(BigInteger n, SecureRandom random)
    {
        int nBitLength = n.bitLength();
        BigInteger k = new BigInteger(nBitLength, random);

        while (k.equals(BigInteger.ZERO) || k.compareTo(n) >= 0)
        {
            k = new BigInteger(nBitLength, random);
        }

        return k;
    }
}