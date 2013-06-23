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

public class ECCommittedSplitSecret
{
    private final BigInteger[] shares;
    private final ECPoint[] commitments;
    private final BigInteger[] witnesses;

    public ECCommittedSplitSecret(BigInteger[] shares, BigInteger[] witnesses, ECPoint[] commitments)
    {
        this.shares = shares;
        this.commitments = commitments;
        this.witnesses = witnesses;
    }

    public ECCommittedSecretShare[] getShares()
    {
        ECCommittedSecretShare[] committedSecretShares = new ECCommittedSecretShare[shares.length];

        for (int i = 0; i != committedSecretShares.length; i++)
        {
            committedSecretShares[i] = new ECCommittedSecretShare(shares[i], witnesses[i], commitments);
        }

        return committedSecretShares;
    }
}
