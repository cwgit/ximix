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

public class ShuffleOptions
{
    public static class Builder
    {
        private final String transformName;

        private String keyID;

        public Builder(String transformName)
        {
             this.transformName = transformName;
        }

        public Builder setKeyID(String keyID)
        {
            this.keyID = keyID;

            return this;
        }

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

    public String getTransformName()
    {
        return  transformName;
    }

    public String getKeyID()
    {
        return  keyID;
    }
}
