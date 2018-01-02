using System;

namespace Org.BouncyCastle.Crypto
{
	/// <remarks>The interface stream ciphers conform to.</remarks>
    public interface IStreamCipher
    {
		/// <summary>The name of the algorithm this cipher implements.</summary>
		string AlgorithmName { get; }

		/**
         * Initialise the cipher.
         *
         * @param forEncryption if true the cipher is initialised for
         *  encryption, if false for decryption.
         * @param param the key and other data required by the cipher.
         * @exception ArgumentException if the parameters argument is
         * inappropriate.
         */
        void Init(bool forEncryption, ICipherParameters parameters);

		/**
         * encrypt/decrypt a single byte returning the result.
         *
         * @param in the byte to be processed.
         * @return the result of processing the input byte.
         */
        byte ReturnByte(byte input);

        /**
         * process a block of bytes from in putting the result into out.
         *
         * @param in the input byte array.
         * @param inOff the offset into the in array where the data to be processed starts.
         * @param len the number of bytes to be processed.
         * @param out the output buffer the processed bytes go into.
         * @param outOff the offset into the output byte array the processed data stars at.
         * @exception DataLengthException if the output buffer is too small.
         */
        void ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff);

		/// <summary>
		/// Reset the cipher to the same state as it was after the last init (if there was one).
		/// </summary>
		void Reset();
    }
}
