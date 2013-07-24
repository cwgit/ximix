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

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;

public class BLSCommittedSecretShare
{
    private final BigInteger share;
    private final BigInteger witness;
    private final Element[]  commitmentFactors;

    public BLSCommittedSecretShare(BigInteger share, BigInteger witness, Element[] commitmentFactors)
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

    public Element[] getCommitmentFactors()
    {
        return commitmentFactors;
    }

    /**
     * Return the commitment value for a particular share number.
     *
     * @param shareNumber the number of this share.
     * @return the EC point representing the committed value.
     */
    public Element getCommitment(int shareNumber)
    {
        Element commitment = commitmentFactors[0];
        BigInteger alpha = BigInteger.valueOf(shareNumber + 1);  // note: this is related to a value.
        BigInteger powAplha = BigInteger.ONE;

        for (int k = 1; k < commitmentFactors.length; k++)
        {
            powAplha = powAplha.multiply(alpha);

            commitment = commitment.add(commitmentFactors[k].duplicate().mul(powAplha));
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
    public boolean isRevealed(int shareNumber, BLS01Parameters domainParams, BigInteger hValue)
    {
        Element h = domainParams.getG().duplicate().mul(hValue);

        return getCommitment(shareNumber).equals(domainParams.getG().duplicate().mul(share).add(h.duplicate().mul(witness)));
    }
}
