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
package org.cryptoworkshop.ximix.common.util;

/**
 * The basic operation listener interface.
 *
 * @param <E>  the type used to convey status and error details.
 */
public interface OperationListener<E>
{
    /**
     * Called whn the operation is completed.
     */
    void completed();

    /**
     * Called when a status message is sent.
     *
     * @param statusObject an object providing some status details.
     */
    void status(E statusObject);

    /**
     * Called if the operation fails and will not complete.
     *
     * @param errorObject an object providing some error details.
     */
    void failed(E errorObject);
}
