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

import java.io.IOException;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.XimixObjectIdentifiers;

public class SubjectPublicKeyInfoFactory
{
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(BLS01PublicKeyParameters keyParameters)
        throws IOException
    {
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(XimixObjectIdentifiers.ximixAlgorithmsExperimental, new DERSequence(
            new ASN1Encodable[]
                {
                    new DERUTF8String(keyParameters.getParameters().getCurveParameters().toString()),
                    new DEROctetString(keyParameters.getParameters().getG().toBytes())
                })), keyParameters.getPk().toBytes());
    }
}
