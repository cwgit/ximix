package org.cryptoworkshop.ximix.node.crypto.test;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.cryptoworkshop.ximix.node.crypto.key.message.ECCommittedSecretShareMessage;
import org.junit.Assert;
import org.junit.Test;

public class ECCommittedSecretShareMessageTest
{
    //
    // values for a 2 party sharing
    //
    BigInteger h = BigInteger.valueOf(1000001);

    BigInteger v1 = new BigInteger("46256380476987701737467067480859855791692743111241540391114075765406046655847");
    BigInteger w1 = new BigInteger("63087594472829829766093438692257677001677189269249418282997356499607986082454");
    byte[]     cf1_1 = Base64.decode("BK3a5Ikc6/a6b1aAwwj5ZCKNoTT20pMTKO/VDH4IG4wY8DvNwhb47Zx3mH3zXFRpkN+U09zoeZhp3gNmBOOOYVo=");
    byte[]     cf1_2 = Base64.decode("BC76Juj9+eQIr0wHvmfQJyMnphru5e7/2d85y56XGubf9qyups6Xt02IpXuDEJS801tK6LLIeL0IzdzzzjQs+Q0=");

    BigInteger v2 = new BigInteger("82850491220132271858359672637732073296148810653712519068735062468009133670638");
    BigInteger w2 = new BigInteger("41438032090535211511459116759698432349698063488307241614154823830599485561348");
    byte[]     cf2_1 = Base64.decode("BK3a5Ikc6/a6b1aAwwj5ZCKNoTT20pMTKO/VDH4IG4wY8DvNwhb47Zx3mH3zXFRpkN+U09zoeZhp3gNmBOOOYVo=");
    byte[]     cf2_2 = Base64.decode("BC76Juj9+eQIr0wHvmfQJyMnphru5e7/2d85y56XGubf9qyups6Xt02IpXuDEJS801tK6LLIeL0IzdzzzjQs+Q0=");

    @Test
    public void testEncoding()
        throws IOException
    {
        X9ECParameters params = SECNamedCurves.getByName("secp256r1");
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());

        ECPoint[]   factors = new ECPoint[] { domainParams.getCurve().decodePoint(cf1_1), domainParams.getCurve().decodePoint(cf1_2) };
        ECPoint[]   qFactors = new ECPoint[] { domainParams.getCurve().decodePoint(cf2_2), domainParams.getCurve().decodePoint(cf2_1) };

        ECCommittedSecretShareMessage msg1 = new ECCommittedSecretShareMessage(0, v1, w1, factors, domainParams.getCurve().decodePoint(cf1_1), qFactors);

        ECCommittedSecretShareMessage msg2 = ECCommittedSecretShareMessage.getInstance(domainParams.getCurve(), msg1.getEncoded());

        Assert.assertEquals(v1, msg2.getValue());
        Assert.assertEquals(w1, msg2.getWitness());
        Assert.assertEquals(factors[0], msg2.getCommitmentFactors()[0]);
        Assert.assertEquals(factors[1], msg2.getCommitmentFactors()[1]);
        Assert.assertEquals(factors[0], msg2.getQ());
        Assert.assertEquals(qFactors[0], msg2.getQCommitmentFactors()[0]);
        Assert.assertEquals(qFactors[1], msg2.getQCommitmentFactors()[1]);
    }
}
