using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
	/// <remarks>An OutputStream for an TLS connection.</remarks>
	public class TlsOuputStream
		: BaseOutputStream
	{
		private TlsProtocolHandler handler;

		internal TlsOuputStream(
			TlsProtocolHandler handler)
		{
			this.handler = handler;
		}

		public override void Write(
			byte[]	buf,
			int		offset,
			int		len)
		{
			this.handler.WriteData(buf, offset, len);
		}

		public void WriteByte(int arg0)
		{
			byte[] buf = new byte[1];
			buf[0] = (byte)arg0;
			this.Write(buf, 0, 1);
		}

		public override void Close()
		{
			handler.Close();
			base.Close();
		}

		public override void Flush()
		{
			handler.Flush();
		}
	}
}