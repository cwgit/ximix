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
package org.cryptoworkshop.ximix.node.mixnet.transform;

/**
 * Base interface a transform should conform to.
 */
public interface Transform
    extends Cloneable
{
    /**
     * Return the name of the transform.
     *
     * @return the transform's name.
     */
    String getName();

    /**
     * Initialise the transform.
     *
     * @param o an appropriate initialisation object.
     */
    void init(Object o);

    /**
     * Transform a message.
     *
     * @param message the data representing the message to be transformed.
     * @return the transformed message as a byte array.
     */
    byte[] transform(byte[] message);

    /**
     * Return any data generated during the last transform that could be used to verify the transform later.
     *
     * @return data related to the last transform carried out as a byte array.
     */
    byte[] getLastDetail();

    /**
     * Return a deep copy of the transform object suitable for use by an individual thread.
     *
     * @return transform deep copy.
     */
    public Transform clone();
}
