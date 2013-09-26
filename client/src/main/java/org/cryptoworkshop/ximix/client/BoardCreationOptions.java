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

/**
 * Options carrier for board creation.
 */
public class BoardCreationOptions
{
    /**
     * Public builder for creating board creation option objects.
     */
    public static class Builder
    {
        private final String boardHost;

        private String backUpHost;

        /**
         * Basic constructor - specify which host is to carry the board.
         *
         * @param boardHost the name of the host to hold the board.
         */
        public Builder(String boardHost)
        {
            this.boardHost = boardHost;
        }

        /**
         * Specify a back up host for the board.
         *
         * @param backUpHost the name of the back up host.
         * @return the current builder.
         */
        public Builder withBackUpHost(String backUpHost)
        {
            this.backUpHost = backUpHost;

            return this;
        }

        public BoardCreationOptions build()
        {
            return new BoardCreationOptions(this);
        }
    }

    private final String boardHost;
    private final String backUpHost;

    private BoardCreationOptions(Builder builder)
    {
        this.boardHost = builder.boardHost;
        this.backUpHost = builder.backUpHost;
    }

    /**
     * Return the name of the host holding the board.
     *
     * @return the name of the board host.
     */
    public String getBoardHost()
    {
        return boardHost;
    }

    /**
     * Return the name of the host holding the backup board.
     *
     * @return the name of the back up host.
     */
    public String getBackUpHost()
    {
        return backUpHost;
    }
}
