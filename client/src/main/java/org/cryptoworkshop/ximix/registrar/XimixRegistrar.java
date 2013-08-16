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

import java.util.List;

/**
 * Registrar which encompasses all the services offered by the peers in the network.
 */
public interface XimixRegistrar
{
    /**
     * Connect to a specific service.
     *
     * @param serviceClass
     * @param <T>
     * @return
     */
    <T> T connect(Class<T> serviceClass)
        throws RegistrarServiceException;

    List<XimixRegistrarFactory.NodeConfig> getConfiguredNodeNames();
}
