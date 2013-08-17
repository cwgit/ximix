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

public class DownloadOptions
{
    public static class Builder
    {
        private String keyID;
        private int threshold;
        private String[] nodesToUse;
        private DecryptionChallengeSpec challengeSpec;

        public Builder()
        {

        }

        public Builder withKeyID(String keyID)
        {
            this.keyID = keyID;

            return this;
        }

        public Builder withThreshold(int threshold)
        {
            this.threshold = threshold;

            return this;
        }

        public Builder withNodes(String... nodesToUse)
        {
            this.nodesToUse = nodesToUse;

            return this;
        }

        public Builder withChallenge(DecryptionChallengeSpec challengeSpec)
        {
            this.challengeSpec = challengeSpec;

            return this;
        }

        public DownloadOptions build()
        {
            return new DownloadOptions(this);
        }
    }

    private final String keyID;
    private final int threshold;
    private final String[] nodesToUse;

    private DownloadOptions(Builder builder)
    {
        this.keyID = builder.keyID;
        this.threshold = builder.threshold;
        this.nodesToUse = builder.nodesToUse.clone();
    }

    public String getKeyID()
    {
        return keyID;
    }

    public int getThreshold()
    {
        return threshold;
    }

    public String[] getNodesToUse()
    {
        return nodesToUse.clone();
    }
}
