using System;
using System.IO;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    public class CmsTypedStream
    {
        private const int BufferSize = 32 * 1024;

		private readonly string	_oid;
        private readonly Stream	_in;
		private readonly int	_bufSize;

		public CmsTypedStream(
            Stream inStream)
			: this(PkcsObjectIdentifiers.Data.Id, inStream, BufferSize)
        {
        }

		public CmsTypedStream(
			string oid,
			Stream inStream)
			: this(oid, inStream, BufferSize)
		{
		}

		public CmsTypedStream(
			string	oid,
			Stream	inStream,
			int		bufSize)
		{
			_oid = oid;
			_bufSize = bufSize;
			_in = new FullReaderStream(inStream, bufSize);
		}

		public string ContentType
        {
			get { return _oid; }
        }

		public Stream ContentStream
        {
			get { return _in; }
        }

		public void Drain()
        {
            byte[] buf = new byte[_bufSize];

			while ((_in.Read(buf, 0, buf.Length) > 0))
            {
                // keep going...
            }

			_in.Close();
        }

		private class FullReaderStream
			: BaseInputStream
        {
            internal Stream _stream;

			internal FullReaderStream(
                Stream	inStream,
				int		bufSize)
            {
				_stream = new BufferedStream(inStream, bufSize);
            }

			public override int ReadByte()
            {
                return _stream.ReadByte();
            }

			public override int Read(
                byte[]	buf,
                int		off,
                int		len)
            {
				// TODO Check this method is correct for len < 1

				int rd = 0;
                int total = 0;

				while (len != 0 && (rd = _stream.Read(buf, off, len)) > 0)
                {
                    off += rd;
                    len -= rd;
                    total += rd;
                }

				// NB: End of _stream returns 0 correctly
				return total;
            }

			public override void Close()
            {
				_stream.Close();
				base.Close();
			}
        }
    }
}
