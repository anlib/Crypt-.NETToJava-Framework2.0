using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    internal class ConstructedOctetStream
        : BaseInputStream
    {
        private readonly Asn1ObjectParser _parser;

        private bool _first = true;
        private Stream _currentStream;

        internal ConstructedOctetStream(
            Asn1ObjectParser parser)
        {
            _parser = parser;
        }

		public override int ReadByte()
        {
            if (_first)
            {
                Asn1OctetString s = (Asn1OctetString)_parser.ReadObject();

                if (s == null)
                {
                    return -1;
                }

                _first = false;
                _currentStream = s.GetOctetStream();
            }
            else if (_currentStream == null)
            {
                return -1;
            }

            int b = _currentStream.ReadByte();

            if (b >= 0)
            {
                return b;
            }

            Asn1OctetString aos = (Asn1OctetString)_parser.ReadObject();

            if (aos == null)
            {
                _currentStream = null;

                return -1;
            }

            _currentStream = aos.GetOctetStream();

            return _currentStream.ReadByte();
        }
    }
}
