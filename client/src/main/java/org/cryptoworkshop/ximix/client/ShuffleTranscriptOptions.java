package org.cryptoworkshop.ximix.client;

import org.cryptoworkshop.ximix.common.util.TranscriptType;

/**
 * Options available for downloading a transcript.
 */
public class ShuffleTranscriptOptions
{
    /**
     * Public builder for creating transcript option objects.
     */
    public static class Builder
    {
        private final TranscriptType transcriptType;

        private byte[] seedValue;
        private int chunkSize;

        /**
         * Base constructor
         *
         * @param transcriptType the type of transcript requested.
         */
        public Builder(TranscriptType transcriptType)
        {
            this.transcriptType = transcriptType;

            this.chunkSize = 10;
        }

        /**
         * Specify that a challenge seed is to be used for determining what witness values are to be collected.
         *
         * @param seedValue the seed to use for the witness collection.
         * @return the current builder instance.
         */
        public Builder withChallengeSeed(byte[] seedValue)
        {
            this.seedValue = seedValue.clone();

            return this;
        }

        /**
         * Specify a chunk size for the records to arrive in - the default is currently 10.
         *
         * @param chunkSize the seed to use for the witness collection.
         * @return the current builder instance.
         */
        public Builder withChunkSize(int chunkSize)
        {
            this.chunkSize = chunkSize;

            return this;
        }

        /**
         * Build an actual shuffle options object suitable for use with services supporting the shuffle operation.
         *
         * @return a ShuffleOptions object.
         */
        public ShuffleTranscriptOptions build()
        {
            return new ShuffleTranscriptOptions(this);
        }
    }

    private final TranscriptType transcriptType;
    private final byte[] seedValue;
    private final int chunkSize;

    private ShuffleTranscriptOptions(Builder builder)
    {
        this.transcriptType = builder.transcriptType;
        this.seedValue = builder.seedValue;
        this.chunkSize = builder.chunkSize;
    }

    /**
     * Return the type of the transcript of interest.
     *
     * @return transcript type we want to download.
     */
    public TranscriptType getTranscriptType()
    {
        return transcriptType;
    }

    /**
     * Return a random seed value for establishing which message indexes we are interested in.
     *
     * @return a random seed value for indexes of messages the transcript should be for.
     */
    public byte[] getSeedValue()
    {
        if (seedValue != null)
        {
            return seedValue;
        }

        return null;
    }

    /**
     * Return the number of transcript records to be downloaded by a listener in a batch.
     *
     * @return number of transcript records in each download.
     */
    public int getChunkSize()
    {
        return chunkSize;
    }
}
