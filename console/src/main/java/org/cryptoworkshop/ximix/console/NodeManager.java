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
package org.cryptoworkshop.ximix.console;

import org.cryptoworkshop.ximix.console.util.Traversal;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class NodeManager
{

    private static NodeManager nodeManager = new NodeManager();

    private List<NodeAdapter> nodes = new ArrayList<NodeAdapter>();

    public static NodeManager manager()
    {
        return nodeManager;
    }

    void addNodeAdapter(NodeAdapter adapter)
    {
        if (nodes.contains(adapter))
        {
            throw new IllegalArgumentException("Already added.");
        }
        nodes.add(adapter);
    }

    /**
     * Traverse the list of nodes.
     *
     * @param adapters The adapter.
     */
    void nodes(Traversal<NodeAdapter> adapters)
    {
        for (NodeAdapter na : nodes)
        {
            adapters.element(na);
        }
    }


}
