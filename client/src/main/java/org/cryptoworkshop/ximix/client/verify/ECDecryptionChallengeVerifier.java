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
package org.cryptoworkshop.ximix.client.verify;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.message.ChallengeLogMessage;

/**
 * Verifier for a decryption challenge log stream
 */
public class ECDecryptionChallengeVerifier
{
    private final ECPublicKeyParameters pubKey;
    private final ByteArrayInputStream logStream;

    public ECDecryptionChallengeVerifier(ECPublicKeyParameters pubKey, ByteArrayInputStream logStream)
    {
        this.pubKey = pubKey;
        this.logStream = logStream;
    }

    /**
     * Verify that the decryption challenge transcript is valid, throwing an exception if an issue is found..
     *
     * @throws TranscriptVerificationException on verification failure.
     */
    public void verify()
        throws TranscriptVerificationException
    {
        ASN1InputStream aIn = new ASN1InputStream(logStream);

        try
        {
            ASN1Object obj;
            while ((obj = aIn.readObject()) != null)
            {
                ChallengeLogMessage logMessage = ChallengeLogMessage.getInstance(obj);

                ECPoint[] sourceMessage = logMessage.getSourceMessage();
                ECPoint[] challengeResults = logMessage.getChallengeResult();

                if (!logMessage.hasPassed())
                {
                    throw new TranscriptVerificationException("Log message indicates challenge did not pass.");
                }

                for (int i = 0; i != sourceMessage.length; i++)
                {
                    sourceMessage[i] = sourceMessage[i].multiply(logMessage.getM());
                }

                if (!Arrays.equals(sourceMessage, challengeResults))
                {
                    throw new TranscriptVerificationException("Challenge results do not match combined source message and m value.");
                }
            }
        }
        catch (TranscriptVerificationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Exception validating decryption challenge transcript: " + e.getMessage(), e);
        }
    }
}
