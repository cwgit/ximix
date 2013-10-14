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
package org.cryptoworkshop.ximix.node.crypto.operator.bc;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.node.crypto.operator.ECPrivateKeyOperator;

/**
 * An Elliptic Curve private key operator
 */
public class BcECPrivateKeyOperator
    implements ECPrivateKeyOperator
{
    private final int sequenceNo;
    private final ECDomainParameters domainParameters;
    private final BigInteger privateKeyValue;

    /**
     * Base constructor.
     *
     * @param sequenceNo the step in the threshold sequence this private value is associated with.
     * @param domainParameters the domain parameters associated with this operator.
     * @param privateKeyValue the private key value for this sequence step.
     */
    public BcECPrivateKeyOperator(int sequenceNo, ECDomainParameters domainParameters, BigInteger privateKeyValue)
    {
        this.sequenceNo = sequenceNo;
        this.domainParameters = domainParameters;
        this.privateKeyValue = privateKeyValue;
    }

    @Override
    public ECDomainParameters getDomainParameters()
    {
        return domainParameters;
    }

    @Override
    public int getSequenceNo()
    {
        return sequenceNo;
    }

    @Override
    public <T> T transform(T value)
    {
        if (value instanceof ECPoint)
        {
            return (T)((ECPoint)value).multiply(privateKeyValue);
        }
        if (value instanceof BigInteger)
        {
            return (T)((BigInteger)value).multiply(privateKeyValue);
        }

        throw new IllegalArgumentException("Unknown parameter type passed to EC transform");
    }
}
