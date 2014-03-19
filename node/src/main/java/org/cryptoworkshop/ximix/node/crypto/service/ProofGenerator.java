package org.cryptoworkshop.ximix.node.crypto.service;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.crypto.ECDecryptionProof;
import org.cryptoworkshop.ximix.node.crypto.operator.ECPrivateKeyOperator;

// An application of:
// An application of "Efficient Cryptographic Protocol Design Based on Distributed El Gamal Encryption, F. Brandt, and
// "How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios" by D. Bernhard, O. Prereira, and B. Warinschi.
class ProofGenerator
{
    private final ECPrivateKeyOperator operator;
    private final ECDomainParameters domainParameters;
    private final ECPoint q;
    private final SecureRandom random;

    ProofGenerator(ECPrivateKeyOperator operator, SecureRandom random)
    {
        this.operator = operator;
        this.domainParameters = operator.getDomainParameters();
        this.q = operator.transform(domainParameters.getG());
        this.random = random;
    }

    private BigInteger computeChallenge(ECPoint a, ECPoint b, ECPoint c, ECPair partial, ECPoint g)
    {
        SHA256Digest sha256 = new SHA256Digest();

        addIn(sha256, a);
        addIn(sha256, b);
        addIn(sha256, c);

        addIn(sha256, partial.getX());
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

    ECDecryptionProof computeProof(ECPoint c, ECPair partial)
    {
        BigInteger s = generateS();
        ECPoint    a = domainParameters.getG().multiply(s).normalize();
        ECPoint    b = c.multiply(s).normalize();

        BigInteger challenge = computeChallenge(a, b, c, partial, domainParameters.getG());

        BigInteger f = s.add(operator.transform(challenge)).mod(domainParameters.getN());

        return new ECDecryptionProof(a, b, f);
    }

    private BigInteger generateS()
    {
        BigInteger order = domainParameters.getN();
        int nBitLength = order.bitLength();
        BigInteger s = new BigInteger(nBitLength, random);

        while (s.equals(BigInteger.ZERO) || s.compareTo(order) >= 0)
        {
            s = new BigInteger(nBitLength, random);
        }

        return s;
    }
}
