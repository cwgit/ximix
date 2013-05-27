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
package org.cryptoworkshop.ximix.mixnet.task;

import org.cryptoworkshop.ximix.common.message.UploadMessage;
import org.cryptoworkshop.ximix.common.service.ServiceContext;
import org.cryptoworkshop.ximix.mixnet.MixNetNodeContext;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;

public class UploadTask
    implements Runnable
{
    private final ServiceContext nodeContext;
    private final UploadMessage message;
    private final BulletinBoard board;

    public UploadTask(ServiceContext nodeContext, BulletinBoard board, UploadMessage message)
    {
        this.nodeContext = nodeContext;
        this.board = board;
        this.message = message;
    }

    public void run()
    {
        board.postMessage(message.getData());
    }
}
