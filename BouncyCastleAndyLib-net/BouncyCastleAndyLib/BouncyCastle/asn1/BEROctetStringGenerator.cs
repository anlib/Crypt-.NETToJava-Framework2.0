using System;
using System.IO;

using Asn1 = Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    public class BerOctetStringGenerator
        : BerGenerator
    {
        public BerOctetStringGenerator(Stream outStream)
            : base(outStream)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.OctetString);
        }

        public BerOctetStringGenerator(
            Stream	outStream,
            int		tagNo,
            bool	isExplicit)
            : base(outStream, tagNo, isExplicit)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.OctetString);
        }

        public Stream GetOctetOutputStream()
        {
            return new BerOctetStream(this);
        }

        public Stream GetOctetOutputStream(
            byte[] buf)
        {
            return new BufferedBerOctetStream(this, buf);
        }

        private class BerOctetStream
            : BaseOutputStream
        {
            private byte[] _buf = new byte[1];
            private readonly BerOctetStringGenerator _gen;

            internal BerOctetStream(BerOctetStringGenerator gen)
            {
                this._gen = gen;
            }

            public override void WriteByte(
                byte b)
            {
                _buf[0] = b;

				byte[] bytes = new DerOctetString(_buf).GetEncoded();
                _gen.Out.Write(bytes, 0, bytes.Length);
            }

			public override void Write(
                byte[]	buf,
                int		offSet,
                int		len)
            {
                byte[] bytes = new byte[len];

                Array.Copy(buf, offSet, bytes, 0, len);

                byte[] encoded = new Asn1.DerOctetString(bytes).GetEncoded();
                _gen.Out.Write(encoded, 0, encoded.Length);
            }

            public override void Close()
            {
                _gen.WriteBerEnd();
				base.Close();
			}
        }

		private class BufferedBerOctetStream
            : BaseOutputStream
        {
            private byte[] _buf;
            private int    _off;
            private readonly BerOctetStringGenerator _gen;

			internal BufferedBerOctetStream(BerOctetStringGenerator gen,
                byte[] buf)
            {
                _gen = gen;
                _buf = buf;
                _off = 0;
            }

			public override void WriteByte(
                byte b)
            {
                _buf[_off++] = (byte)b;

                if (_off == _buf.Length)
                {
                    byte[] encoded = new DerOctetString(_buf).GetEncoded();
                    _gen.Out.Write(encoded, 0, encoded.Length);
                    _off = 0;
                }
            }

			// TODO Override Write
//			public override void Write(
//				byte[] buf,
//				int    offSet,
//				int    len)

			public override void Close()
            {
                if (_off != 0)
                {
                    byte[] bytes = new byte[_off];
                    Array.Copy(_buf, 0, bytes, 0, _off);

                    byte[] encoded = new DerOctetString(bytes).GetEncoded();
                    _gen.Out.Write(encoded, 0, encoded.Length);
                }

                _gen.WriteBerEnd();
				base.Close();
			}
        }
    }
}
