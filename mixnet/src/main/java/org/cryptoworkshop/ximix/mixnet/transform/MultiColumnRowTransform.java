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
package org.cryptoworkshop.ximix.mixnet.transform;

import java.io.IOException;

import org.bouncycastle.crypto.ec.ECNewRandomnessTransform;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.ec.ECPairTransform;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.cryptoworkshop.ximix.mixnet.board.asn1.PairSequence;

public class MultiColumnRowTransform
    implements Transform
{
    public static final String NAME = "MultiColumnRowTransform";

    public String getName()
    {
        return NAME;
    }

    public byte[] transform(byte[] message)
    {
        ECPair[] pairs = PairSequence.getInstance(null, message).getECPairs();

        ECPairTransform transform = new ECNewRandomnessTransform();

        ParametersWithRandom params = new ParametersWithRandom(null, new FixedSecureRandom(new byte[] { 10 }));

        transform.init(params);

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
            // TODO: log an error, or maybe trhow an exception
            return message;
        }
    }
}
