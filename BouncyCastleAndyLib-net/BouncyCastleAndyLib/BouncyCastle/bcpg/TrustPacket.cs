using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a trust packet.</remarks>
    public class TrustPacket
        : ContainedPacket
    {
        byte[] levelAndTrustAmount;

		public TrustPacket(
            BcpgInputStream bcpgIn)
        {
            MemoryStream bOut = new MemoryStream();

			int ch;
            while ((ch = bcpgIn.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte) ch);
            }

			levelAndTrustAmount = bOut.ToArray();
        }

		public TrustPacket(
            int trustCode)
        {
			this.levelAndTrustAmount = new byte[]{ (byte)trustCode };
        }

		public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.Trust, levelAndTrustAmount, true);
        }
    }
}
