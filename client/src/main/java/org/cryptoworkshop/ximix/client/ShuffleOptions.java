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
 * Carrier for available options that can be set on bulletin board shuffle.
 */
public class ShuffleOptions
{
    /**
     * Public builder for creating shuffle option objects.
     */
    public static class Builder
    {
        private final String transformName;

        private String keyID;

        /**
         * Base constructor
         *
         * @param transformName the name of the transform to apply.
         */
        public Builder(String transformName)
        {
             this.transformName = transformName;
        }

        /**
         * Flag that extra randomness to messages needs to be further encrypted using the public key associated with keyID.
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
         * Build an actual shuffle options object suitable for use with services supporting the shuffle operation.
         *
         * @return a ShuffleOptions object.
         */
        public ShuffleOptions build()
        {
            return new ShuffleOptions(this);
        }
    }

    private final String transformName;
    private final String keyID;

    private ShuffleOptions(Builder builder)
    {
        this.transformName = builder.transformName;
        this.keyID = builder.keyID;
    }

    /**
     * Return the transform to be applied during the shuffle.
     *
     * @return the name of the transform to use.
     */
    public String getTransformName()
    {
        return  transformName;
    }

    /**
     * Return the id of the public key required for mixing in further randomness.
     *
     * @return key id of key to be used to mix in further randomness.
     */
    public String getKeyID()
    {
        return  keyID;
    }
}
