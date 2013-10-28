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
package org.cryptoworkshop.ximix.client.connection.signing;

/**
 * Object based key to identify particular signing operations.
 */
public class SigID
{
    private final String id;

    /**
     * Base constructor.
     *
     * @param id  an ID associated with a signing operation.
     */
    public SigID(String id)
    {
        this.id = id;
    }

    public String getID()
    {
        return id;
    }

    public int hashCode()
    {
        return id.hashCode();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof SigID)
        {
            SigID other = (SigID)o;

            return this.id.equals(other.id);
        }

        return false;
    }
}
