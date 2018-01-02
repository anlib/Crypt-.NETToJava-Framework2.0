using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
	/// <remarks>An InputStream for an TLS 1.0 connection.</remarks>
	public class TlsInputStream
		: BaseInputStream
	{
		private readonly TlsProtocolHandler handler;

		internal TlsInputStream(
			TlsProtocolHandler handler)
		{
			this.handler = handler;
		}

		public override int Read(
			byte[]	buf,
			int		offset,
			int		len)
		{
			int result = this.handler.ReadApplicationData(buf, offset, len);

			// NB: .NET uses 0 for EOF
			return result < 0 ? 0 : result;
		}

		public override int ReadByte()
		{
			byte[] buf = new byte[1];
			if (this.Read(buf, 0, 1) <= 0)
			{
				return -1;
			}
			return buf[0];
		}

		public override void Close()
		{
			handler.Close();
			base.Close();
		}
	}
}
