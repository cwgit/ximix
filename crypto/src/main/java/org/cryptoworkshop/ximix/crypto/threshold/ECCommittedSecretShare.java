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

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public class ECCommittedSecretShare
{
    private final BigInteger share;
    private final BigInteger witness;
    private final ECPoint[]  commitmentFactors;

    public ECCommittedSecretShare(BigInteger share, BigInteger witness, ECPoint[] commitmentFactors)
    {
        this.share = share;
        this.witness = witness;
        this.commitmentFactors = commitmentFactors;
    }

    /**
     * Return the value of the component of the split secret this share represents.
     *
     * @return the share value.
     */
    public BigInteger getValue()
    {
        return share;
    }

    public BigInteger getWitness()
    {
        return witness;
    }

    public ECPoint[] getCommitmentFactors()
    {
        return commitmentFactors;
    }

    /**
     * Return the commitment value for a particular share number.
     *
     * @param shareNumber the number of this share.
     * @return the EC point representing the committed value.
     */
    public ECPoint getCommitment(int shareNumber)
    {
        ECPoint commitment = commitmentFactors[0];
        BigInteger alpha = BigInteger.valueOf(shareNumber + 1);  // note: this is related to a value.
        BigInteger powAplha = BigInteger.ONE;

        for (int k = 1; k < commitmentFactors.length; k++)
        {
            powAplha = powAplha.multiply(alpha);

            commitment = commitment.add(commitmentFactors[k].multiply(powAplha));
        }

        return commitment;
    }

    /**
     * Return true if the share value is revealed by the commitment we carry, false otherwise.
     *
     * @param shareNumber the number of this share.
     * @param domainParams the domain parameters of the curve we expect to be on.
     * @param hValue the value of h used to commit against.
     * @return true if share is revealed by commitment, false otherwise.
     */
    public boolean isRevealed(int shareNumber, ECDomainParameters domainParams, BigInteger hValue)
    {
        ECPoint h = domainParams.getG().multiply(hValue);

        return getCommitment(shareNumber).equals(domainParams.getG().multiply(share).add(h.multiply(witness)));
    }
}
