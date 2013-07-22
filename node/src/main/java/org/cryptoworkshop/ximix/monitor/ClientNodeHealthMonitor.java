package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;

/**
 *
 */
public class ClientNodeHealthMonitor implements NodeHealthMonitor
{
    private AdminServicesConnection connection = null;

    public ClientNodeHealthMonitor(AdminServicesConnection connection)
    {
        this.connection = connection;
    }
}
