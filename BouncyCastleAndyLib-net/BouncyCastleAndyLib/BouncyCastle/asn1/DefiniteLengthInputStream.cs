using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    class DefiniteLengthInputStream
        : LimitedInputStream
    {
        private int _length;

        internal DefiniteLengthInputStream(
            Stream inStream,
            int length)
            : base(inStream)
        {
            this._length = length;
        }

        public override int ReadByte()
        {
            if (_length-- > 0)
            {
                return _in.ReadByte();
            }

            SetParentEofDetect(true);

            return -1;
        }
    }
}
