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

import org.cryptoworkshop.ximix.common.crypto.Algorithm;

/**
 * Carrier for available options that can be set on signature generation.
 */
public class SignatureGenerationOptions
{
    /**
     * Public builder for creating signature generation option objects.
     */
    public static class Builder
    {
        private final Algorithm algorithm;
        private final String[] parameters;

        private int threshold;
        private String[] nodesToUse;

        public Builder(Algorithm algorithm, String... parameters)
        {
            this.algorithm = algorithm;
            this.parameters = parameters;
        }

        /**
         * Specify the threshold the key was generated at.
         *
         * @param threshold private key threshold.
         * @return the current builder.
         */
        public Builder withThreshold(int threshold)
        {
            this.threshold = threshold;

            return this;
        }

        /**
         * Specify the list of possible nodes to take part in the signing.
         * <p>
         * Note: the number of nodes needs to be at least at the threshold for the key.
         * </p>
         * @param nodesToUse the names of the nodes to use.
         * @return the current builder.
         */
        public Builder withNodes(String... nodesToUse)
        {
            this.nodesToUse = nodesToUse;

            return this;
        }

        public SignatureGenerationOptions build()
        {
            return new SignatureGenerationOptions(this);
        }
    }

    private final Algorithm algorithm;
    private final String[] parameters;
    private final int threshold;
    private final String[] nodesToUse;

    private SignatureGenerationOptions(Builder builder)
    {
        this.algorithm = builder.algorithm;
        this.parameters = builder.parameters;
        this.threshold = builder.threshold;
        this.nodesToUse = builder.nodesToUse;
    }

    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    public String[] getParameters()
    {
        return parameters.clone();
    }

    public String[] getNodesToUse()
    {
        return nodesToUse;
    }

    public int getThreshold()
    {
        return threshold;
    }
}
