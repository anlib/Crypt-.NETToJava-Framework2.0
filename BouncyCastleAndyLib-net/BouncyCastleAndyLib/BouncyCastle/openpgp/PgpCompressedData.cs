using System;
using System.IO;

//using ICSharpCode.SharpZipLib.BZip2;
//using ICSharpCode.SharpZipLib.Zip.Compression;
//using ICSharpCode.SharpZipLib.Zip.Compression.Streams;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Compressed data objects</remarks>
    public class PgpCompressedData
		: PgpObject
    {
        private readonly CompressedDataPacket data;

		public PgpCompressedData(
            BcpgInputStream bcpgInput)
        {
            data = (CompressedDataPacket) bcpgInput.ReadPacket();
        }

		/// <summary>The algorithm used for compression</summary>
        public CompressionAlgorithmTag Algorithm
        {
			get { return data.Algorithm; }
        }

		/// <summary>Get the raw input stream contained in the object.</summary>
        public Stream GetInputStream()
        {
            return data.GetInputStream();
        }

		/// <summary>Return an uncompressed input stream which allows reading of the compressed data.</summary>
        public Stream GetDataStream()
        {
            switch (this.Algorithm)
            {
				case CompressionAlgorithmTag.Uncompressed:
					return this.GetInputStream();
                //case CompressionAlgorithmTag.Zip:
                //    return new InflaterInputStream(this.GetInputStream(), new Inflater(true));
                //case CompressionAlgorithmTag.ZLib:
                //    return new InflaterInputStream(this.GetInputStream());
                //case CompressionAlgorithmTag.BZip2:
                //    return new BZip2InputStream(this.GetInputStream());
                default:
                    throw new PgpException("can't recognise compression algorithm: " + this.Algorithm);
            }
        }
    }
}
