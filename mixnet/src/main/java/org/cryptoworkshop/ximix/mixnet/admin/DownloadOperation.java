package org.cryptoworkshop.ximix.mixnet.admin;

import org.cryptoworkshop.ximix.common.operation.Operation;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.mixnet.DownloadOptions;

public interface DownloadOperation
{
    /**
     * Download the contents of a board.
     *
     * @param boardName
     * @throws org.cryptoworkshop.ximix.common.service.ServiceConnectionException
     */
    Operation<DownloadOperationListener> downloadBoardContents(
            String boardName,
            DownloadOptions options)
        throws ServiceConnectionException;
}
