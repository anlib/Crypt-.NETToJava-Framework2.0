using System;
using System.IO;

//using ICSharpCode.SharpZipLib.BZip2;
//using ICSharpCode.SharpZipLib.Zip.Compression;
//using ICSharpCode.SharpZipLib.Zip.Compression.Streams;

using Org.BouncyCastle.Asn1.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Class for producing compressed data packets.</remarks>
	public class PgpCompressedDataGenerator
		: IStreamGenerator
	{
		private readonly CompressionAlgorithmTag algorithm;
		private readonly int compression;

		private Stream dOut;
		private BcpgOutputStream pkOut;

		public PgpCompressedDataGenerator(
			CompressionAlgorithmTag algorithm)
			: this(algorithm, 1)
		{
		}

		public PgpCompressedDataGenerator(
			CompressionAlgorithmTag	algorithm,
			int						compression)
		{
			switch (algorithm)
			{
				case CompressionAlgorithmTag.Uncompressed:
				case CompressionAlgorithmTag.Zip:
				case CompressionAlgorithmTag.ZLib:
				case CompressionAlgorithmTag.BZip2:
					break;
				default:
					throw new ArgumentException("unknown compression algorithm", "algorithm");
			}

            //if (compression != 0)
            //{
            //    if ((compression < 0) || (compression > 0))
            //    {
            //        throw new ArgumentException("unknown compression level: " + compression);
            //    }
            //}

			this.algorithm = algorithm;
			this.compression = compression;
		}

		/// <summary>Return an output stream which will save the data being written to
		/// the compressed object.</summary>
		public Stream Open(
			Stream outStr)
		{
			if (dOut != null)
				throw new InvalidOperationException("generator already in open state");
			if (outStr == null)
				throw new ArgumentNullException("outStr");

			this.pkOut = new BcpgOutputStream(outStr, PacketTag.CompressedData);

			doOpen();

			return new WrappedGeneratorStream(this, dOut);
		}

		/// <summary>
		/// Return an output stream which will compress the data as it is written to it.
		/// The stream will be written out in chunks according to the size of the passed in buffer.
		/// <p>
		/// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
		/// bytes worth of the buffer will be used.
		/// </p>
		/// <p>
		/// <b>Note</b>: using this may break compatibility with RFC 1991 compliant tools.
		/// Only recent OpenPGP implementations are capable of accepting these streams.
		/// </p>
		/// </summary>
		public Stream Open(
			Stream	outStr,
			byte[]	buffer)
		{
			if (dOut != null)
				throw new InvalidOperationException("generator already in open state");
			if (outStr == null)
				throw new ArgumentNullException("outStr");
			if (buffer == null)
				throw new ArgumentNullException("buffer");

			this.pkOut = new BcpgOutputStream(outStr, PacketTag.CompressedData, buffer);

			doOpen();

			return new WrappedGeneratorStream(this, dOut);
		}

		private void doOpen()
		{
			pkOut.WriteByte((byte) algorithm);

			switch (algorithm)
			{
				case CompressionAlgorithmTag.Uncompressed:
					dOut = pkOut;
					break;
                //case CompressionAlgorithmTag.Zip:
                //    dOut = new DeflaterOutputStream(pkOut, new Deflater(compression, true));
                //    break;
                //case CompressionAlgorithmTag.ZLib:
                //    dOut = new DeflaterOutputStream(pkOut, new Deflater(compression, false));
                //    break;
                //case CompressionAlgorithmTag.BZip2:
                //    dOut = new BZip2OutputStream(pkOut);
                //    break;
				default:
					// Constructor should guard against this possibility
					throw new ExecutionEngineException();
			}
		}

		/// <summary>Close the compressed object.</summary>summary>
		public void Close()
		{
			if (dOut != null)
			{
				//switch (algorithm)
				//{
				//	case CompressionAlgorithmTag.BZip2:
				//		// TODO No Finish method on BZip2OutputStream
				//		break;
				//	case CompressionAlgorithmTag.Zip:
				//	case CompressionAlgorithmTag.ZLib:
				//		((DeflaterOutputStream) dOut).Finish();
				//		break;
				//}
				//dOut.Flush();

				// TODO IgnoreClose stuff is a workaround for BZip2OutputStream problem above
				pkOut.IgnoreClose = true;
				dOut.Close();
				pkOut.IgnoreClose = false;

				pkOut.Finish();
				pkOut.Flush();

				dOut = null;
				pkOut = null;
			}
		}
	}
}
