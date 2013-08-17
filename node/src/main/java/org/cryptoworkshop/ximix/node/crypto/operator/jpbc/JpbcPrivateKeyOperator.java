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
package org.cryptoworkshop.ximix.node.crypto.operator.jpbc;

import java.math.BigInteger;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.cryptoworkshop.ximix.node.crypto.operator.BLSPrivateKeyOperator;

public class JpbcPrivateKeyOperator
    implements BLSPrivateKeyOperator
{
    private final int sequenceNo;
    private final BLS01Parameters domainParameters;
    private final Element privateKeyValue;

    public JpbcPrivateKeyOperator(int sequenceNo, BLS01Parameters domainParameters, BigInteger privateKeyValue)
    {
        this.sequenceNo = sequenceNo;
        this.domainParameters = domainParameters;                               // TODO: maybe pass pairing in instead.
        this.privateKeyValue = PairingFactory.getPairing(domainParameters.getCurveParameters()).getZr().newElement(privateKeyValue);
    }

    @Override
    public BLS01Parameters getDomainParameters()
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
        if (value instanceof Element)
        {
            return (T)((Element)value).duplicate().powZn(privateKeyValue);
        }

        throw new IllegalArgumentException("Unknown parameter type passed to EC transform");
    }
}
