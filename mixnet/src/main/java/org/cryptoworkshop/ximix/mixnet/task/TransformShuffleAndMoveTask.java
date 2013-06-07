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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.cryptoworkshop.ximix.common.message.MoveMessage;
import org.cryptoworkshop.ximix.common.service.ServiceContext;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.mixnet.service.TransferBoardService;
import org.cryptoworkshop.ximix.mixnet.transform.MultiColumnRowTransform;
import org.cryptoworkshop.ximix.mixnet.transform.Transform;
import org.cryptoworkshop.ximix.registrar.RegistrarServiceException;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;

public class TransformShuffleAndMoveTask
    implements Runnable
{
    private final ServiceContext nodeContext;
    private final MoveMessage message;
    private final BulletinBoardRegistry boardRegistry;

    public TransformShuffleAndMoveTask(ServiceContext nodeContext, BulletinBoardRegistry boardRegistry, MoveMessage message)
    {
        this.nodeContext = nodeContext;
        this.boardRegistry = boardRegistry;
        this.message = message;
    }

    public void run()
    {
        BulletinBoard board = boardRegistry.getBoard(message.getBoardName());
        Transform transform = new MultiColumnRowTransform();
        List<byte[]> transformedMessages = new ArrayList<byte[]>();

        for (byte[] message : board)
        {
            byte[] transformed = transform.transform(message);

            transformedMessages.add(transformed);
        }

        Map<String, XimixRegistrar> registrarMap = nodeContext.getParameter(ServiceContext.NODE_REGISTRAR_MAP);

        try
        {
            TransferBoardService transferService = registrarMap.get(message.getNodeName()).connect(TransferBoardService.class);

            transferService.signalStart(message.getBoardName());

            for (byte[] message : transformedMessages)
            {
                 transferService.uploadMessage(message);
            }

            transferService.signalEnd(message.getBoardName());
        }
        catch (RegistrarServiceException e)
        {
            // TODO: log?
        }
    }
}
