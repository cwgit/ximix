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
package org.cryptoworkshop.ximix.node.mixnet.service;

import java.util.HashSet;
import java.util.Set;

import org.cryptoworkshop.ximix.common.asn1.message.BoardDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.PermuteAndMoveMessage;

class MessageEvaluator
{
    private static final Set<CommandMessage.Type> needToBeHostingType = new HashSet<>();
    private static final Set<CommandMessage.Type> alwaysHandleType = new HashSet<>();

    static
    {
        needToBeHostingType.add(CommandMessage.Type.SUSPEND_BOARD);
        needToBeHostingType.add(CommandMessage.Type.ACTIVATE_BOARD);
        needToBeHostingType.add(CommandMessage.Type.BOARD_DOWNLOAD_LOCK);
        needToBeHostingType.add(CommandMessage.Type.BOARD_DOWNLOAD_UNLOCK);
        needToBeHostingType.add(CommandMessage.Type.BOARD_SHUFFLE_LOCK);
        needToBeHostingType.add(CommandMessage.Type.BOARD_SHUFFLE_UNLOCK);

        alwaysHandleType.add(CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE);
        alwaysHandleType.add(CommandMessage.Type.INITIATE_INTRANSIT_BOARD);
        alwaysHandleType.add(CommandMessage.Type.TRANSFER_TO_BOARD);
        alwaysHandleType.add(CommandMessage.Type.UPLOAD_TO_BOARD);
        alwaysHandleType.add(CommandMessage.Type.TRANSFER_TO_BOARD_ENDED);
        alwaysHandleType.add(CommandMessage.Type.CLEAR_BACKUP_BOARD);
        alwaysHandleType.add(CommandMessage.Type.TRANSFER_TO_BACKUP_BOARD);
        alwaysHandleType.add(CommandMessage.Type.RETURN_TO_BOARD);
        alwaysHandleType.add(CommandMessage.Type.FETCH_BOARD_STATUS);
        alwaysHandleType.add(CommandMessage.Type.DOWNLOAD_SHUFFLE_TRANSCRIPT);
        alwaysHandleType.add(CommandMessage.Type.DOWNLOAD_SHUFFLE_TRANSCRIPT_STEPS);
        alwaysHandleType.add(CommandMessage.Type.GET_BOARD_HOST);
    }

    private final BoardIndex boardIndex;

    MessageEvaluator(CapabilityMessage capabilityMessage)
    {
        this.boardIndex = new BoardIndex(capabilityMessage);
    }

    public boolean isAbleToHandle(Message message)
    {
        Enum type = message.getType();

        if (type instanceof ClientMessage.Type)
        {
            if (type == ClientMessage.Type.UPLOAD_TO_BOARD)
            {
                BoardUploadMessage uploadMessage = BoardUploadMessage.getInstance(message.getPayload());

                if (boardIndex.hasBoard(uploadMessage.getBoardName()))
                {
                    return true;
                }
            }
        }
        else
        {
            if  (needToBeHostingType.contains(type))
            {
                BoardMessage boardMessage = BoardMessage.getInstance(message.getPayload());

                return boardIndex.hasBoard(boardMessage.getBoardName());
            }

            if (type == CommandMessage.Type.DOWNLOAD_BOARD_CONTENTS)
            {
                BoardDownloadMessage boardMessage = BoardDownloadMessage.getInstance(message.getPayload());

                return boardIndex.hasBoard(boardMessage.getBoardName());
            }

            if (type == CommandMessage.Type.START_SHUFFLE_AND_MOVE_BOARD_TO_NODE)
            {
                PermuteAndMoveMessage boardMessage = PermuteAndMoveMessage.getInstance(message.getPayload());

                return boardIndex.hasBoard(boardMessage.getBoardName());
            }

            return alwaysHandleType.contains(type);
        }

        return false;
    }
}
