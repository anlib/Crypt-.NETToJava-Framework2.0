using System;
using System.IO;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * reader for signature sub-packets
    */
    public class SignatureSubpacketsParser
    {
        Stream input;
        public SignatureSubpacketsParser(
            Stream input)
        {
            this.input = input;
        }
        private void ReadFully(
            byte[] Buffer,
            int off,
            int len)
        {
            while (len > 0)
            {
                int l = input.Read(Buffer, off, len);
                if (l <= 0)
                {
                    throw new EndOfStreamException();
                }
                off += l;
                len -= l;
            }
        }
        public SignatureSubpacket ReadPacket()
        {
            int l = input.ReadByte();
            if (l < 0)
            {
                return null;
            }
            int bodyLen = 0;
            if (l < 192)
            {
                bodyLen = l;
            }
            else if (l < 223)
            {
                bodyLen = ((l - 192) << 8) + (input.ReadByte()) + 192;
            }
            else if (l == 255)
            {
                bodyLen = (input.ReadByte() << 24) | (input.ReadByte() << 16)
                    |  (input.ReadByte() << 8)  | input.ReadByte();
            }
            int tag = input.ReadByte();
            if (tag < 0)
            {
                throw new EndOfStreamException("unexpected EOF reading signature sub packet");
            }
            byte[] data = new byte[bodyLen - 1];
            this.ReadFully(data, 0, data.Length);

            bool IsCritical = ((tag & 0x80) != 0);
            SignatureSubpacketTag type = (SignatureSubpacketTag)(tag & 0x7f);
            switch (type)
            {
                case SignatureSubpacketTag.CreationTime:
                    return new SignatureCreationTime(IsCritical, data);
                case SignatureSubpacketTag.KeyExpireTime:
                    return new KeyExpirationTime(IsCritical, data);
                case SignatureSubpacketTag.ExpireTime:
                    return new SignatureExpirationTime(IsCritical, data);
                case SignatureSubpacketTag.Revocable:
                    return new Revocable(IsCritical, data);
                case SignatureSubpacketTag.Exportable:
                    return new Exportable(IsCritical, data);
                case SignatureSubpacketTag.IssuerKeyId:
                    return new IssuerKeyId(IsCritical, data);
                case SignatureSubpacketTag.TrustSig:
                    return new TrustSignature(IsCritical, data);
                case SignatureSubpacketTag.PreferredCompressionAlgorithms:
                case SignatureSubpacketTag.PreferredHashAlgorithms:
                case SignatureSubpacketTag.PreferredSymmetricAlgorithms:
                    return new PreferredAlgorithms(type, IsCritical, data);
                case SignatureSubpacketTag.KeyFlags:
                    return new KeyFlags(IsCritical, data);
                case SignatureSubpacketTag.PrimaryUserId:
                    return new PrimaryUserId(IsCritical, data);
                case SignatureSubpacketTag.SignerUserId:
                    return new SignerUserId(IsCritical, data);
            }
            return new SignatureSubpacket(type, IsCritical, data);
        }
    }
}
