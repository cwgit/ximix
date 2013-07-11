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
package org.cryptoworkshop.ximix.crypto.key;

import java.io.IOException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.cryptoworkshop.ximix.common.service.KeyType;
import org.cryptoworkshop.ximix.crypto.key.message.ECKeyGenParams;

public interface KeyManager
{
    boolean hasPrivateKey(String keyID);

    boolean isSigningKey(String keyID);

    AsymmetricCipherKeyPair generateKeyPair(String keyID, KeyType algorithm, int numberOfPeers, ECKeyGenParams keyGenParams);

    SubjectPublicKeyInfo fetchPublicKey(String keyID)
        throws IOException;
}
