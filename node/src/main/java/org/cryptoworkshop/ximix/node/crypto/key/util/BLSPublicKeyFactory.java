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
package org.cryptoworkshop.ximix.node.crypto.key.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Factor for producing BLS keys from SubjectPublicKeyInfo objects.
 */
public class BLSPublicKeyFactory
{
    /**
     * Create BLS01PublicKeyParameters from an ASN.1 encoding of a SubjectPublicKeyInfo object.
     *
     * @param encoding the byte array representing the ASN.1 encoding.
     * @return a BLS public key.
     */
    public static BLS01PublicKeyParameters createKey(byte[] encoding)
    {
        return createKey(SubjectPublicKeyInfo.getInstance(encoding));
    }

    /**
     * Create BLS01PublicKeyParameters from an ASN.1 encoding of a SubjectPublicKeyInfo object.
     *
     * @param publicKeyInfo the info structure containing the BLS public key.
     * @return a BLS public key.
     */
    public static BLS01PublicKeyParameters createKey(SubjectPublicKeyInfo publicKeyInfo)
    {
        AlgorithmIdentifier   algId = publicKeyInfo.getAlgorithm();
        CurveParameters       curveParameters;
        Element G;
        Pairing pairing;
        try
        {
            ASN1Sequence parameters = ASN1Sequence.getInstance(algId.getParameters());

            curveParameters = new DefaultCurveParameters().load(new ByteArrayInputStream(DERUTF8String.getInstance(parameters.getObjectAt(0)).getString().getBytes("UTF8")));
            pairing = PairingFactory.getPairing(curveParameters);
            G = pairing.getG2().newElement();
            G.setFromBytes(DEROctetString.getInstance(parameters.getObjectAt(1)).getOctets());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Unable to support encoding: " + e.getMessage(), e);
        }

        BLS01Parameters       blsParameters = new BLS01Parameters(curveParameters, G.getImmutable());
        Element               pK = pairing.getG2().newElement();

        pK.setFromBytes(publicKeyInfo.getPublicKeyData().getBytes());

        return new BLS01PublicKeyParameters(blsParameters, pK.getImmutable());
    }
}
