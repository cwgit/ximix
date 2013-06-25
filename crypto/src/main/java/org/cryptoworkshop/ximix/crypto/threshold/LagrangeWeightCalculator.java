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

import org.bouncycastle.math.ec.ECPoint;

/**
 * A basic calculator for Lagrangian weights for a given number of peers in a given field.
 */
public class LagrangeWeightCalculator
{
    private final int numberOfPeers;
    private final BigInteger fieldSize;
    private final BigInteger[] alphas;

    /**
     * Construct a calculator over the specified field to calculate weights for
     * used to process secrets shared among the specified number of peers
     *
     * @param numberOfPeers the number of peers among which the secret is shared
     * @param fieldSize size of the group's field.
     */
    public LagrangeWeightCalculator(int numberOfPeers, BigInteger fieldSize)
    {
        this.numberOfPeers = numberOfPeers;
        this.fieldSize = fieldSize;

        this.alphas = new BigInteger[numberOfPeers];

        for (int i = 0; i < numberOfPeers; i++)
        {
            alphas[i] = BigInteger.valueOf(i + 1);
        }
    }

    /**
     * Computes the Lagrange weights used for interpolation to reconstruct the shared secret.
     *
     * @param activePeers an ordered array of peers available, entries are null if no peer present.
     * @return the Lagrange weights
     */
    public BigInteger[] computeWeights(Object[] activePeers)
    {
        BigInteger[] weights = new BigInteger[numberOfPeers];

        for (int i = 0; i < numberOfPeers; i++)
        {
            if (activePeers[i] != null)
            {
                BigInteger nominator = BigInteger.ONE;
                BigInteger denominator = BigInteger.ONE;

                for (int peerIndex = 0; peerIndex < numberOfPeers; peerIndex++)
                {
                    if (peerIndex != i && activePeers[peerIndex] != null)
                    {
                        nominator = nominator.multiply(alphas[peerIndex]).mod(fieldSize);
                        denominator = denominator.multiply(alphas[peerIndex].subtract(alphas[i]).mod(fieldSize)).mod(fieldSize);
                    }
                }

                weights[i] = nominator.multiply(denominator.modInverse(fieldSize)).mod(fieldSize);
            }
        }

        return weights;
    }
}