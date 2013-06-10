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
package org.cryptoworkshop.ximix.mixnet.admin;

import org.bouncycastle.asn1.DERSequence;
import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MoveMessage;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;

public class ClientMixnetCommandService
    implements MixnetCommandService
{
    private AdminServicesConnection connection;

    public ClientMixnetCommandService(AdminServicesConnection connection)
    {
        this.connection = connection;
    }

    public void doShuffleAndMove(String boardName, ShuffleOptions options, String... nodes)
        throws ServiceConnectionException
    {
        for (String node : nodes)
        {
             connection.sendMessage(node, CommandMessage.Type.SUSPEND_BOARD, new BoardMessage(boardName));
        }

        for (int i = 0; i != nodes.length; i++)
        {
            String curNode = nodes[i];
            String nextNode = nodes[(i + 1) % nodes.length];

             connection.sendMessage(curNode, CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new MoveMessage(nextNode, boardName));
        }

        for (String node : nodes)
        {
             connection.sendMessage(node, CommandMessage.Type.ACTIVATE_BOARD, new BoardMessage(boardName));
        }
    }
}
