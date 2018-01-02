using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a PGP Signature sub-packet.
    */
    public class UserAttributeSubpacket
    {
        UserAttributeSubpacketTag                type;

        internal byte[]   data;

        internal UserAttributeSubpacket(
            UserAttributeSubpacketTag            type,
            byte[]         data)
        {
            this.type = type;
            this.data = data;
        }

        public UserAttributeSubpacketTag SubpacketType
        {
            get
            {
                return type;
            }
        }

        /**
        * return the generic data making up the packet.
        */
        public byte[] GetData()
        {
            return data;
        }

        public void Encode(
            Stream    os)
        {
            int    bodyLen = data.Length + 1;

            if (bodyLen < 192)
            {
                os.WriteByte((byte)bodyLen);
            }
            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;

                os.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                os.WriteByte((byte)bodyLen);
            }
            else
            {
                os.WriteByte(0xff);
                os.WriteByte((byte)(bodyLen >> 24));
                os.WriteByte((byte)(bodyLen >> 16));
                os.WriteByte((byte)(bodyLen >> 8));
                os.WriteByte((byte)bodyLen);
            }

            os.WriteByte((byte) type);
            os.Write(data, 0, data.Length);
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
            {
                return true;
            }

            if (obj is UserAttributeSubpacket)
            {
                UserAttributeSubpacket   other = (UserAttributeSubpacket)obj;

                if (other.type != this.type)
                {
                    return false;
                }

                if (other.data.Length != this.data.Length)
                {
                    return false;
                }

                for (int i = 0; i != this.data.Length; i++)
                {
                    if (this.data[i] != other.data[i])
                    {
                        return false;
                    }
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            int    code = (int) this.type;

            for (int i = 0; i != this.data.Length; i++)
            {
                code ^= (this.data[i] & 0xff) << (8 * (i % 4));
            }

            return code;
        }
    }
}
