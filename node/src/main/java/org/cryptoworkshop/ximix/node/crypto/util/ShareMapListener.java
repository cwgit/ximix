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
 * Listener interface for events in a share map.
 *
 * @param <K> the type of the key used to index the map.
 * @param <V> the value type associated with the shares in the map.
 */
public interface ShareMapListener<K, V>
{
    /**
     * Notify that a share is fully built.
     *
     * @param shareMap the map containing the share.
     * @param id the share's key in the map.
     */
    public void shareCompleted(ShareMap<K, V> shareMap, K id);
}
