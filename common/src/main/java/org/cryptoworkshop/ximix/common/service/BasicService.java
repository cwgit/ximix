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
package org.cryptoworkshop.ximix.common.service;

import java.util.HashMap;
import java.util.Map;

import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

public abstract class BasicService
    implements Service
{
    private final ListenerHandler<ServiceStatisticsListener> listenerHandler;
    private final ServiceStatisticsListener statisticsNotifier;

    protected final NodeContext nodeContext;

    public BasicService(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;

        listenerHandler = new DecoupledListenerHandlerFactory(nodeContext.getDecoupler(Decoupler.SERVICES)).createHandler(ServiceStatisticsListener.class);
        statisticsNotifier = listenerHandler.getNotifier();
    }

    public void trigger(ServiceEvent event)
    {
        if (event.getType() == ServiceEvent.Type.PUBLISH_STATISTICS)
        {
            statisticsNotifier.statisticsUpdate(this, getCurrentStatistics());
        }
    }

    public void addStatisticsListener(ServiceStatisticsListener statisticsListener)
    {
         listenerHandler.addListener(statisticsListener);
    }

    // TODO: when all is said and done, this should be abstract, non-abstract at the moment so can be added progressively.
    public Map<String,Object> getCurrentStatistics()
    {
        return new HashMap<>();
    }
}
