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

import java.io.InputStream;
import java.util.Map;

import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.util.Operation;

/**
 * Interface defining available operation result download operations.
 */
public interface DownloadShuffleResultOperation
{
    /**
     * Decrypt and return the results of a set of operations after validation.
     *
     * @param boardName name of the board to download from.
     * @param options the options to use in the decryption/download process.
     * @param seedCommitmentMap a collection of input streams representing the seed commitments from each node.
     * @param seedAndWitnessesMap a collection of input streams representing the seed and witness values from each node.
     * @param generalTranscripts a collection of input streams representing the general transcripts at each step.
     * @param witnessTranscipts a collection of input streams representing the witness transcripts at each step.
     * @param defaultListener the listener to be sent messages
     */
    Operation<DownloadOperationListener> downloadShuffleResult(
        String boardName,
        DownloadShuffleResultOptions options,
        Map<String, InputStream> seedCommitmentMap, Map<String, InputStream> seedAndWitnessesMap, Map<Integer, InputStream> generalTranscripts,
        Map<Integer, InputStream> witnessTranscipts,
        DownloadOperationListener defaultListener)
        throws ServiceConnectionException;
}
