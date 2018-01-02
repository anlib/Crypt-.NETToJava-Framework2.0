using System;
using System.IO;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>A multiple precision integer</remarks>
    public class MPInteger
        : BcpgObject
    {
        private readonly BigInteger val;

        public MPInteger(
            BcpgInputStream bcpgIn)
        {
			if (bcpgIn == null)
				throw new ArgumentNullException("bcpgIn");

			int length = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            byte[] bytes = new byte[(length + 7) / 8];

            bcpgIn.ReadFully(bytes);

            this.val = new BigInteger(1, bytes);
        }

		public MPInteger(
            BigInteger val)
        {
			if (val == null)
				throw new ArgumentNullException("val");

			this.val = val;
        }

		public BigInteger Value
        {
            get { return val; }
        }

        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            int length = val.BitLength;

            bcpgOut.WriteByte((byte) (length >> 8));
            bcpgOut.WriteByte((byte) length);

            byte[] bytes = val.ToByteArray();

            if (bytes[0] == 0)
            {
                bcpgOut.Write(bytes, 1, bytes.Length - 1);
            }
            else
            {
                bcpgOut.Write(bytes);
            }
        }
    }
}
