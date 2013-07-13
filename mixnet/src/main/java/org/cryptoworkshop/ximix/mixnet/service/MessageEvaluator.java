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
package org.cryptoworkshop.ximix.mixnet.service;

import org.cryptoworkshop.ximix.common.message.BoardDownloadMessage;
import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;

class MessageEvaluator
{
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
            if  (type == CommandMessage.Type.SUSPEND_BOARD
                || type == CommandMessage.Type.ACTIVATE_BOARD
                || type == CommandMessage.Type.BOARD_DOWNLOAD_LOCK
                || type == CommandMessage.Type.BOARD_DOWNLOAD_UNLOCK
                || type == CommandMessage.Type.BOARD_SHUFFLE_LOCK
                || type == CommandMessage.Type.BOARD_SHUFFLE_UNLOCK)
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

            if (type == CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE)
            {
                return true;
            }

            if (type == CommandMessage.Type.INITIATE_INTRANSIT_BOARD)
            {
                return true;
            }

            if (type == CommandMessage.Type.TRANSFER_TO_BOARD)
            {
                return true;
            }

            if (type == CommandMessage.Type.TRANSFER_TO_BOARD_ENDED)
            {
                return true;
            }

            if  (type == CommandMessage.Type.SHUFFLE_AND_RETURN_BOARD)
            {
                return true;
            }

            if  (type == CommandMessage.Type.FETCH_BOARD_STATUS)
            {
                return true;
            }
        }

        return false;
    }
}
