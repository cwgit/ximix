package org.cryptoworkshop.ximix.node.crypto.service;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.node.crypto.operator.ECPrivateKeyOperator;

// An application of:
// An application of "Efficient Cryptographic Protocol Design Based on Distributed El Gamal Encryption, F. Brandt, and
// "How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios" by D. Bernhard, O. Prereira, and B. Warinschi.
class ProofGenerator
{
    BigInteger computeChallenge(ECPair[] ciphers, ECPair[] partials)
    {
        SHA256Digest sha256 = new SHA256Digest();

        for (ECPair cText : ciphers)
        {
            addIn(sha256, cText.getX());
            addIn(sha256, cText.getY());
        }

        for (ECPair plain : partials)
        {
            addIn(sha256, plain.getX());
            addIn(sha256, plain.getY());
        }

        byte[] res = new byte[sha256.getDigestSize()];

        sha256.doFinal(res, 0);

        return new BigInteger(1, res);
    }

    private void addIn(SHA256Digest sha256, ECPoint point)
    {
        byte[] enc = point.getEncoded();

        sha256.update(enc, 0, enc.length);
    }

    ECPoint computeProof(ECPoint pTxt, BigInteger challenge, ECDomainParameters domainParameters, ECPrivateKeyOperator operator)
    {
        return pTxt.add(domainParameters.getG().multiply(operator.transform(challenge))).normalize();
    }
}
