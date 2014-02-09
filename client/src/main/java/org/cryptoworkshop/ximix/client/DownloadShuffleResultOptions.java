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
package org.cryptoworkshop.ximix.client;

/**
 * Carrier for available options that can be set on shuffled result bulletin board download.
 */
public class DownloadShuffleResultOptions
{
    /**
     * Public builder for creating download option objects.
     */
    public static class Builder
    {
        private String keyID;
        private int threshold;
        private String[] nodesToUse;
        private boolean isWithPairing;

        /**
         * Base constructor
         */
        public Builder()
        {

        }

        /**
         * Flag that messages need to be decrypted using the private key associated with keyID.
         *
         * @param keyID identity of the private key to use.
         * @return the current builder instance.
         */
        public Builder withKeyID(String keyID)
        {
            this.keyID = keyID;

            return this;
        }

        /**
         * Flag that messages require at least threshold nodes to handle the decryption.
         *
         * @param threshold the number of nodes representing the threshold to be reached.
         * @return the current builder instance.
         */
        public Builder withThreshold(int threshold)
        {
            this.threshold = threshold;

            return this;
        }

        /**
         * Flag which nodes to use for any threshold operations.
         *
         * @param nodesToUse the node names to be used.
         * @return the current builder instance.
         */
        public Builder withNodes(String... nodesToUse)
        {
            this.nodesToUse = nodesToUse;

            return this;
        }

        public Builder withPairingEnabled(boolean isWithPairing)
        {
            this.isWithPairing = isWithPairing;

            return this;
        }

        /**
         * Build an actual download options object suitable for use with services supporting the download operation.
         *
         * @return a DownloadOptions object.
         */
        public DownloadShuffleResultOptions build()
        {
            return new DownloadShuffleResultOptions(this);
        }
    }

    private final String keyID;
    private final int threshold;
    private final String[] nodesToUse;
    private final boolean isWithPairing;

    private DownloadShuffleResultOptions(Builder builder)
    {
        this.keyID = builder.keyID;
        this.threshold = builder.threshold;
        this.nodesToUse = builder.nodesToUse.clone();
        this.isWithPairing = builder.isWithPairing;
    }

    /**
     * Return the keyID for the key to use to decrypt messages.
     *
     * @return id of the key to use.
     */
    public String getKeyID()
    {
        return keyID;
    }

    /**
     * Return the threshold number of nodes to use for decryption operations.
     *
     * @return the number of nodes required to take part in a decryption.
     */
    public int getThreshold()
    {
        return threshold;
    }

    /**
     * Return whether two shuffles on a node should be treated as paired.
     *
     * @return true if pairing is the case, false otherwise.
     */
    public boolean isPairingEnabled()
    {
        return isWithPairing;
    }

    /**
     * Return the names of the nodes to choose the threshold number of nodes from.
     *
     * @return the node names to be used.
     */
    public String[] getNodesToUse()
    {
        return nodesToUse.clone();
    }
}
