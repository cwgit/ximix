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
 * Carrier for available options that can be set on key generation.
 */
public class KeyGenerationOptions
{
    /**
     * Public builder for creating key generation option objects.
     */
    public static class Builder
    {
        private final Algorithm algorithm;
        private final String[] parameters;

        private int threshold;
        private String[] nodesToUse;

        /**
         * Basic constructor, specify the algorithm and any parameters required.
         *
         * @param algorithm the algorithm the key is for.
         * @param parameters the parameters to use.
         */
        public Builder(Algorithm algorithm, String... parameters)
        {
            this.algorithm = algorithm;
            this.parameters = parameters;
        }

        /**
         * Flag that the private key should be recoverable with a minimum of threshold nodes.
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
         * Flag which nodes to use for the threshold operations.
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
         * Build the actual key generation options to be passed to the key generation service.
         *
         * @return the appropriate KeyGenerationOptions object.
         */
        public KeyGenerationOptions build()
        {
            return new KeyGenerationOptions(this);
        }
    }

    private final Algorithm algorithm;
    private final String[] parameters;
    private final int threshold;
    private final String[] nodesToUse;

    private KeyGenerationOptions(Builder builder)
    {
        this.algorithm = builder.algorithm;
        this.parameters = builder.parameters;
        this.threshold = builder.threshold;
        this.nodesToUse = builder.nodesToUse;
    }

    /**
     * Return the algorithm id the generated key is to be used for.
     *
     * @return the algorithm id.
     */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return a string representation of the parameter set for key generation.
     *
     * @return an array of string defining the parameter set to be used in the generation.
     */
    public String[] getParameters()
    {
        return parameters.clone();
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

    /**
     * Return the minimum number of nodes required to recover a private key.
     *
     * @return the number of nodes required to recover the private key.
     */
    public int getThreshold()
    {
        return threshold;
    }
}
