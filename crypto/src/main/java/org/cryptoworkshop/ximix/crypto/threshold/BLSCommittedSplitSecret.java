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

import it.unisa.dia.gas.jpbc.Element;

public class BLSCommittedSplitSecret
    extends SplitSecret
{
    private final Element[] commitments;
    private final BigInteger[] witnesses;

    public BLSCommittedSplitSecret(BigInteger[] shares, BigInteger[] coefficients, BigInteger[] witnesses, Element[] commitments)
    {
        super(shares, coefficients);

        this.commitments = commitments;
        this.witnesses = witnesses;
    }

    public BLSCommittedSecretShare[] getCommittedShares()
    {
        BigInteger[] shares = this.getShares();
        BLSCommittedSecretShare[] committedSecretShares = new BLSCommittedSecretShare[shares.length];

        for (int i = 0; i != committedSecretShares.length; i++)
        {
            committedSecretShares[i] = new BLSCommittedSecretShare(shares[i], witnesses[i], commitments);
        }

        return committedSecretShares;
    }
}
