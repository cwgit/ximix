package org.cryptoworkshop.ximix.crypto.key.util;

import java.io.IOException;
import java.math.BigInteger;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.cryptoworkshop.ximix.common.asn1.XimixObjectIdentifiers;

public class PrivateKeyInfoFactory
{
    public static PrivateKeyInfo createPrivateKeyInfo(BigInteger value, BLS01Parameters parameters)
        throws IOException
    {
        return new PrivateKeyInfo(new AlgorithmIdentifier(XimixObjectIdentifiers.ximixAlgorithmsExperimental, new DERSequence(
                    new ASN1Encodable[]
                        {
                            new DERUTF8String(parameters.getCurveParameters().toString()),
                            new DEROctetString(parameters.getG().toBytes())
                        })), new ASN1Integer(value));
    }
}
