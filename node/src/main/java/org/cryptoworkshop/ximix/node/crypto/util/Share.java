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

/**
 * Base class for a share.
 *
 * @param <T> the value type the share is associated with.
 */
public abstract class Share<T>
{
    private final int sequenceNo;
    private final T value;

    /**
     * Base constructor.
     *
     * @param sequenceNo the share's sequence number in the sharing process,
     * @param value the share's value.
     */
    protected Share(int sequenceNo, T value)
    {
        this.sequenceNo = sequenceNo;
        this.value = value;
    }

    public int getSequenceNo()
    {
        return sequenceNo;
    }

    public T getValue()
    {
        return value;
    }

    public abstract Share<T> add(Share<T> value);
}
