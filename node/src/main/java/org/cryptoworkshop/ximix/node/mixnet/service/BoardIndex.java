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

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.asn1.message.BoardCapabilities;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;

/**
 * Simple class for providing lookup of board presence based on caoability messages.
 */
public class BoardIndex
{
    private final CapabilityMessage capabilityMessage;

    public BoardIndex(CapabilityMessage capabilityMessage)
    {
        this.capabilityMessage = capabilityMessage;
    }

    public boolean hasBoard(String boardName)
    {

        for (ASN1Encodable enc : capabilityMessage.getDetails())
        {
            BoardCapabilities details = BoardCapabilities.getInstance(enc);

            if (details.getBoardName().equals(boardName))
            {
                return true;
            }
        }

        return false;
    }
}
