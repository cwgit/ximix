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
package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.*;

/**
 * Request capabilities from another node.
 */
public class RequestCapabilities
    extends ASN1Object
{

    /**
     * Capability request type.
     */
    public static enum Type
    {
        /**
         * Request all capabilities.
         */
        ALL
    }

    private Type type = Type.ALL;


    /**
     * Create for type.
     *
     * @param type The type.
     */
    public RequestCapabilities(Type type)
    {
        this.type = type;
    }

    private RequestCapabilities(ASN1Enumerated ane)
    {
        this.type = Type.values()[ane.getValue().intValue()];
    }

    /**
     * Get an instance, accepts RequestCapabilities object or ASN1Enumerated.
     *
     * @param o
     * @return
     */
    public static final RequestCapabilities getInstance(Object o)
    {
        if (o instanceof RequestCapabilities)
        {
            return (RequestCapabilities)o;
        }

        if (o != null)
        {
            return new RequestCapabilities(ASN1Enumerated.getInstance(o));
        }

        return null;
    }


    public Type getType()
    {
        return type;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Enumerated(type.ordinal());
    }
}
