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
package org.cryptoworkshop.ximix.common.crypto;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Basic holder for a Chaum-Pedersen proof of decryption
 */
public class ECDecryptionProof
{
    private final ECPoint a;
    private final ECPoint b;
    private final BigInteger r;

    /**
     * Base constructor.
     *
     * @param a commitment on G
     * @param b commitment on cipher text X component
     * @param r response to challenge value
     */
    public ECDecryptionProof(ECPoint a, ECPoint b, BigInteger r)
    {
        this.a = a;
        this.b = b;
        this.r = r;
    }

    public ECPoint getA()
    {
        return a;
    }

    public ECPoint getB()
    {
        return b;
    }

    public BigInteger getR()
    {
        return r;
    }

    /**
     * Return true if the decryption verifies
     *
     * @param pubKey public key corresponding to private value used.
     * @param c the point representing the cipher text
     * @param pTxt the point representing the plain text
     * @return true if plain text matches proof, false otherwise.
     */
    public boolean isVerified(ECPublicKeyParameters pubKey, ECPoint c, ECPoint pTxt)
    {
        ECPoint g = pubKey.getParameters().getG();
        BigInteger challenge = computeChallenge(a, b, c, pTxt, g, pubKey.getQ());

        return g.multiply(this.getR()).normalize().equals(this.getA().add(pubKey.getQ().multiply(challenge)).normalize()) // correct public key check
            && c.multiply(this.getR()).normalize().equals(this.getB().add(pTxt.multiply(challenge)).normalize());  // correct decryption check
    }

    private BigInteger computeChallenge(ECPoint a, ECPoint b, ECPoint c, ECPoint partial, ECPoint g, ECPoint q)
    {
        SHA256Digest sha256 = new SHA256Digest();

        addIn(sha256, a);
        addIn(sha256, b);
        addIn(sha256, c);

        addIn(sha256, partial);
        addIn(sha256, g);
        addIn(sha256, q);

        byte[] res = new byte[sha256.getDigestSize()];

        sha256.doFinal(res, 0);

        return new BigInteger(1, res);
    }

    private void addIn(SHA256Digest sha256, ECPoint point)
    {
        byte[] enc = point.getEncoded(true);

        sha256.update(enc, 0, enc.length);
    }
}
