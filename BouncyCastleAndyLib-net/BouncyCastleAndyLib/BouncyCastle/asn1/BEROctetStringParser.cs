using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
	public class BerOctetStringParser
		: Asn1OctetStringParser
	{
		private readonly Asn1ObjectParser _parser;

		internal BerOctetStringParser(
			Asn1ObjectParser parser)
		{
			_parser = parser;
		}

		public Stream GetOctetStream()
		{
			return new ConstructedOctetStream(_parser);
		}

		public Asn1Object ToAsn1Object()
		{
			MemoryStream bOut = new MemoryStream();
			Stream inStream = this.GetOctetStream();
			int ch;

			try
			{
				while ((ch = inStream.ReadByte()) >= 0)
				{
					bOut.WriteByte((byte) ch);
				}
			}
			catch (IOException e)
			{
				throw new InvalidOperationException("IOException converting stream to byte array: " + e.Message, e);
			}

			return new BerOctetString(bOut.ToArray());
		}
	}
}
