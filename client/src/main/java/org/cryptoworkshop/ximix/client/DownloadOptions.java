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
 * Carrier for available options that can be set on bulletin board download.
 */
public class DownloadOptions
{
    /**
     * Public builder for creating download option objects.
     */
    public static class Builder
    {
        private String keyID;
        private int threshold;
        private String[] nodesToUse = new String[0];
        private DecryptionChallengeSpec challengeSpec;

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

        /**
         * Flag how decryption challenges should be managed..
         *
         * @param challengeSpec a specification for which messages to challenge on and where to log.
         * @return the current builder instance.
         */
        public Builder withChallengeSpec(DecryptionChallengeSpec challengeSpec)
        {
            this.challengeSpec = challengeSpec;

            return this;
        }

        /**
         * Build an actual download options object suitable for use with services supporting the download operation.
         *
         * @return a DownloadOptions object.
         */
        public DownloadOptions build()
        {
            return new DownloadOptions(this);
        }
    }

    private final String keyID;
    private final int threshold;
    private final String[] nodesToUse;
    private final DecryptionChallengeSpec challengeSpec;

    private DownloadOptions(Builder builder)
    {
        this.keyID = builder.keyID;
        this.threshold = builder.threshold;
        this.nodesToUse = builder.nodesToUse.clone();
        this.challengeSpec = builder.challengeSpec;
    }

    /**
     * Return the specification to show how decryption challenges are to be generated and logged.
     *
     * @return the DecryptionChallengeSpec describing how to handle challenges.
     */
    public DecryptionChallengeSpec getChallengeSpec()
    {
        return challengeSpec;
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
     * Return the names of the nodes to choose the threshold number of nodes from.
     *
     * @return the node names to be used.
     */
    public String[] getNodesToUse()
    {
        return nodesToUse.clone();
    }
}
