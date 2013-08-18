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
package org.cryptoworkshop.ximix.node.service;

import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

public abstract class BasicNodeService
    implements NodeService
{
    private final ListenerHandler<ServiceStatisticsListener> listenerHandler;
    private final ServiceStatisticsListener statisticsNotifier;

    protected final NodeContext nodeContext;
    protected final CrossSection statistics;


    public BasicNodeService(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;
        this.statistics = new CrossSection(nodeContext.getDecoupler(Decoupler.MONITOR), nodeContext.getEventNotifier());
        listenerHandler = new DecoupledListenerHandlerFactory(nodeContext.getDecoupler(Decoupler.SERVICES), nodeContext.getEventNotifier()).createHandler(ServiceStatisticsListener.class);
        statisticsNotifier = listenerHandler.getNotifier();

    }


    public void trigger(ServiceEvent event)
    {
        if (event.getType() == ServiceEvent.Type.PUBLISH_STATISTICS)
        {
            nodeContext.getDecoupler(Decoupler.SERVICES).execute(new Runnable()
            {
                @Override
                public void run()
                {
                    statisticsNotifier.statisticsUpdate(BasicNodeService.this, statistics.getMap());
                }
            });
        }
    }

    public void addListener(ServiceStatisticsListener statisticsListener)
    {
        listenerHandler.addListener(statisticsListener);
    }

    @Override
    public void removeListener(ServiceStatisticsListener serviceStatisticsListener)
    {
        listenerHandler.removeListener(serviceStatisticsListener);
    }

}
