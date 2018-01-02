using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    abstract class LimitedInputStream
        : BaseInputStream
    {
        protected readonly Stream _in;

        internal LimitedInputStream(
            Stream inStream)
        {
            this._in = inStream;
        }

        internal byte[] ToArray()
        {
            MemoryStream bOut = new MemoryStream();

            int b = 0;
            while ((b = this.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte) b);
            }

            return bOut.ToArray();
        }

        internal Stream GetUnderlyingStream()
        {
            return _in;
        }

        protected void SetParentEofDetect(bool on)
        {
            if (_in is IndefiniteLengthInputStream)
            {
                ((IndefiniteLengthInputStream)_in).SetEofOn00(on);
            }
        }
    }
}
