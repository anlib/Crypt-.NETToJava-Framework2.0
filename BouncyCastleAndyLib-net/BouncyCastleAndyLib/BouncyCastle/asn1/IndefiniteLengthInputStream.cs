using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    class IndefiniteLengthInputStream
        : LimitedInputStream
    {
        private int     _b1;
        private int     _b2;
        private bool _eofReached = false;
        private bool _eofOn00 = true;

        internal IndefiniteLengthInputStream(
            Stream inStream)
            : base(inStream)
        {
            _b1 = inStream.ReadByte();
            _b2 = inStream.ReadByte();
            _eofReached = (_b2 < 0);
        }

        internal void SetEofOn00(
            bool eofOn00)
        {
            _eofOn00 = eofOn00;
        }

        internal void CheckForEof()
        {
            if (_eofOn00 && (_b1 == 0x00 && _b2 == 0x00))
            {
                _eofReached = true;
                SetParentEofDetect(true);
            }
        }

        public override int ReadByte()
        {
            CheckForEof();

            if (_eofReached)
            {
                return -1;
            }

            int b = _in.ReadByte();

            //
            // strictly speaking we should return b1 and b2, but if this happens the stream
            // is corrupted so we are already in trouble.
            //
            if (b < 0)
            {
                _eofReached = true;

                return -1;
            }

            int v = _b1;

            _b1 = _b2;
            _b2 = b;

            return v;
        }
    }
}
