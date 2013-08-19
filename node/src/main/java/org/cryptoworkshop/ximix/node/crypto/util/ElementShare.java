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
package org.cryptoworkshop.ximix.node.crypto.util;

import it.unisa.dia.gas.jpbc.Element;

/**
 * Share object to provide support for constructing shares made up of JPBC Element objects.
 */
public class ElementShare
    extends Share<Element>
{
    public ElementShare(int sequenceNo, Element value)
    {
        super(sequenceNo, value);
    }

    @Override
    public Share<Element> add(Share<Element> other)
    {                                            // just in case, Elements can be mutable
        return new ElementShare(getSequenceNo(), getValue().duplicate().mul(other.getValue()));
    }
}
