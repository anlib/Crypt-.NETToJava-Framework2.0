using System;



namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * Packet holding the key flag values.
    */
    public class KeyFlags
        : SignatureSubpacket
    {
        private static byte[] IntToByteArray(
            int    v)
        {
            byte[]    data = new byte[1];

            data[0] = (byte)v;

            return data;
        }

        public KeyFlags(
            bool    critical,
            byte[]     data)
            : base(SignatureSubpacketTag.KeyFlags, critical, data)
        {
        }

        public KeyFlags(
            bool    critical,
            int        flags)
            : base(SignatureSubpacketTag.KeyFlags, critical, IntToByteArray(flags))
        {
        }

        public int Flags
        {
			get
			{
				return data[0] & 0xff;
			}
        }
    }
}
