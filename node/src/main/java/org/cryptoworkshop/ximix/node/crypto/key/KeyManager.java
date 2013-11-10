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
package org.cryptoworkshop.ximix.node.crypto.key;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;

/**
 * Base interface for a KeyManager
 */
public interface KeyManager
{
    /**
     * Return the manager's ID.
     *
     * @return the ID of the manager.
     */
    String getID();

    /**
     * Return true if the private key keyID is present in the manager, false otherwise.
     *
     * @param keyID the ID of the key of interest.
     * @return true if keyID is present, false otherwise.
     */
    boolean hasPrivateKey(String keyID);

    /**
     * Return true if keyID is a signing key, false otherwise.
     *
     * @param keyID the ID of the key of interest.
     * @return true if keyID for signing, false otherwise.
     */
    boolean isSigningKey(String keyID);

    /**
     * Return a SubjectPublicKeyInfo representing the composite public key associated with keyID.
     *
     * @param keyID the ID of the key of interest.
     * @return a SubjectPublicKeyInfo representing the network public key associated with keyID.
     * @throws IOException if the key cannot be extracted from the manager as an encoding.
     */
    SubjectPublicKeyInfo fetchPublicKey(String keyID)
        throws IOException;

    /**
     * Return a SubjectPublicKeyInfo representing this KeyManager's part of the public key associated with keyID.
     *
     * @param keyID the ID of the key of interest.
     * @return a SubjectPublicKeyInfo representing this KeyManager's part of the public key associated with keyID.
     * @throws IOException if the key cannot be extracted from the manager as an encoding.
     */
    PartialPublicKeyInfo fetchPartialPublicKey(String keyID)
        throws IOException;

    /**
     * Return an encoding of this KeyManager's contents (PKCS#12 format)
     *
     * @param password the password to encrypt with.
     * @return a byte encoding of the KeyManager.
     * @throws IOException if any of the keys in the KeyManager cannot be encoded.
     * @throws GeneralSecurityException if there is an error on encryption.
     */
    byte[] getEncoded(char[] password)
        throws IOException, GeneralSecurityException;

    /**
     * Load this KeyManager with the passed in data (assumed PKCS#12 format).
     *
     * @param password the password to decrypt the data with.
     * @param encoding the encoding of the data to be loaded.
     * @throws IOException if there is an error parsing encoding.
     * @throws GeneralSecurityException if there is an error on decryption.
     */
    void load(char[] password, byte[] encoding)
        throws IOException, GeneralSecurityException;

    /**
     * Add a listener to this KeyManager.
     *
     * @param listener the listener to be added.
     */
    void addListener(KeyManagerListener listener);

    /**
     * Return the operator associated with the private key represented by keyID.
     *
     * @param keyID the keyID we want the operator for.
     * @return a PrivateKeyOperator for keyID.
     */
    PrivateKeyOperator getPrivateKeyOperator(String keyID);
}
