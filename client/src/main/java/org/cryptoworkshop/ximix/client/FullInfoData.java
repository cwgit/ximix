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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * General carrier for status information about a node.
 */
public class FullInfoData
{
    private final Map<String, Object> data;

    /**
     * Base Constructor.
     *
     * @param data a map of (String, Object) representing status values.
     */
    public FullInfoData(Map<String, Object> data)
    {
        this.data = Collections.unmodifiableMap(new HashMap<>(data));
    }

    /**
     * Return the data map contained in this information object.
     *
     * @return a map of (String, Object) representing status values.
     */
    public Map<String, Object> getDataMap()
    {
        return data;
    }
}
