using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpEncryptedData
    {
        internal class TruncatedStream
            : BaseInputStream
        {
            private const int LookaheadSize = 22;

            private byte[] lookAhead = new byte[LookaheadSize];
            private int bufPtr;
            private Stream inputStream;

            internal TruncatedStream(
                Stream inputStream)
            {
				for (int i = 0; i != lookAhead.Length; i++)
				{
					lookAhead[i] = (byte) inputStream.ReadByte();
				}
//                bufPtr = 0;
                this.inputStream = inputStream;
            }

			public override int ReadByte()
            {
                int ch = inputStream.ReadByte();

                if (ch < 0) return -1;

                int c = (int) lookAhead[bufPtr];
                lookAhead[bufPtr++] = (byte) ch;
                bufPtr %= LookaheadSize;

                return c;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
				// TODO Something like this should be faster
				// but need to avoid creating big temp buffers
//				byte[] temp = new byte[count];
//				int numRead = inputStream.Read(temp, 0, count);
//
//				if (numRead > 0)
//				{
//					int pos = 0;
//					do
//					{
//						buffer[offset++] = lookAhead[bufPtr];
//						lookAhead[bufPtr++] = temp[pos++];
//						bufPtr %= LookaheadSize;
//					}
//					while (pos < numRead);
//				}
//
//				return numRead;

                int pos = offset;
                try
                {
                    int end = offset + count;
                    while (pos < end)
                    {
                        int ch = inputStream.ReadByte();

                        if (ch < 0) break;

                        buffer[pos++] = lookAhead[bufPtr];
                        lookAhead[bufPtr++] = (byte) ch;
                        bufPtr %= LookaheadSize;
                    }
                }
                catch (IOException ioe)
                {
                    if (pos == offset) throw ioe;
                }
                return pos - offset;
            }
            internal byte[] GetLookAhead()
            {
                byte[] tmp = new byte[lookAhead.Length];

				Array.Copy(lookAhead, bufPtr, tmp, 0, lookAhead.Length - bufPtr);
				Array.Copy(lookAhead, 0, tmp, lookAhead.Length - bufPtr, bufPtr);

				return tmp;
            }
        }

		internal InputStreamPacket   encData;
        internal Stream              encStream;
        internal TruncatedStream     truncStream;

		internal PgpEncryptedData(
            InputStreamPacket encData)
        {
            this.encData = encData;
        }

		/// <summary>Return the raw input stream for the data stream.</summary>
        public virtual Stream GetInputStream()
        {
            return encData.GetInputStream();
        }

		/// <summary>Return true if the message is integrity protected.</summary>
		/// <returns>True, if there is a modification detection code namespace associated
		/// with this stream.</returns>
        public bool IsIntegrityProtected()
        {
			return encData is SymmetricEncIntegrityPacket;
        }

		/// <summary>Note: This can only be called after the message has been read.</summary>
		/// <returns>True, if the message verifies, false otherwise</returns>
        public bool Verify()
        {
            if (!this.IsIntegrityProtected())
            {
                throw new PgpException("data not integrity protected.");
            }

			DigestStream dIn = (DigestStream) encStream;

			//
            // make sure we are at the end.
            //
            while (encStream.ReadByte() >= 0)
            {
				// do nothing
            }

			//
            // process the MDC packet
            //
			byte[] lookAhead = truncStream.GetLookAhead();

			IDigest hash = dIn.ReadDigest();
			hash.BlockUpdate(lookAhead, 0, 2);
			byte[] digest = DigestUtilities.DoFinal(hash);

			byte[] streamDigest = new byte[digest.Length];
			Array.Copy(lookAhead, 2, streamDigest, 0, streamDigest.Length);

			return Arrays.AreEqual(digest, streamDigest);
        }
    }
}
