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
package org.cryptoworkshop.ximix.client;

import java.io.OutputStream;

/**
 * Basic specification for describing how Zero Knowledge proofs for Decryption are to be generated
 * during downloads.
 */
public class DecryptionChallengeSpec
{
    private final MessageChooser chooser;
    private final OutputStream logStream;

    public DecryptionChallengeSpec(MessageChooser chooser, OutputStream logStream)
    {
        this.chooser = chooser;
        this.logStream = logStream;
    }

    /**
     * Return a chooser to decide which messages to issue challenges on.
     *
     * @return message chooser for deciding when to challenge.
     */
    public MessageChooser getChooser()
    {
        return chooser;
    }

    /**
     * Return the output stream that the transaction log for the decryption proofs is to be written to.
     *
     * @return an output stream to receive log messages.
     */
    public OutputStream getLogStream()
    {
        return logStream;
    }
}
