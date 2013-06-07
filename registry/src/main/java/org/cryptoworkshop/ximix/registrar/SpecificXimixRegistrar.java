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
package org.cryptoworkshop.ximix.registrar;

/**
 * A registrar that contains the services associated with a specific node.
 */
public interface SpecificXimixRegistrar
    extends XimixRegistrar
{
    /**
     * Return the name of the node the services accessed by this registrar are hosted on.
     *
     * @return node name for this services connection.
     */
    String getNodeName();
}
