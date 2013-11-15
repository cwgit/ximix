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
package org.cryptoworkshop.ximix.node.mixnet.transform;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.ec.ECFixedTransform;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.ec.ECPairFactorTransform;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;

/**
 * A transform that can handle multiple columns of EC points in a single row.
 */
public class MultiColumnRowTransform
    implements Transform
{
    public static final String NAME = "MultiColumnRowTransform";

    private ECPublicKeyParameters parameters;
    private ECPairFactorTransform transform;

    public String getName()
    {
        return NAME;
    }

    public void init(Object o)
    {
        this.parameters = (ECPublicKeyParameters)o;

        BigInteger kValue = generateK(parameters.getParameters().getN(), new SecureRandom()); // TODO: make configurable?

        transform = new ECFixedTransform(kValue);

        transform.init(parameters);
    }

    public byte[] transform(byte[] message)
    {
        ECPair[] pairs = PairSequence.getInstance(parameters.getParameters().getCurve(), message).getECPairs();

        for (int i = 0; i != pairs.length; i++)
        {
            pairs[i] = transform.transform(pairs[i]);
        }

        try
        {
            return new PairSequence(pairs).getEncoded();
        }
        catch (IOException e)
        {
            // TODO: log an error, or maybe throw an exception
            return message;
        }
    }

    public byte[] getLastDetail()
    {
        return transform.getTransformValue().toByteArray();
    }

    private BigInteger generateK(BigInteger n, SecureRandom random)
    {
        int                    nBitLength = n.bitLength();
        BigInteger             k = new BigInteger(nBitLength, random);

        while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0))
        {
            k = new BigInteger(nBitLength, random);
        }

        return k;
    }

    public Transform clone()
    {
        return new MultiColumnRowTransform();
    }
}
