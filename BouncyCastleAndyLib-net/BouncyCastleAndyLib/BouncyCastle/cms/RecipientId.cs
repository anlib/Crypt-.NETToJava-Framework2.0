using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    public class RecipientID
        : X509CertStoreSelector
    {
        private byte[] keyIdentifier;

		public byte[] KeyIdentifier
		{
			get { return Arrays.Clone(keyIdentifier); }
			set { keyIdentifier = Arrays.Clone(value); }
		}

		public override int GetHashCode()
        {
            int code = 0;

            if (keyIdentifier != null)
            {
                for (int i = 0; i != keyIdentifier.Length; i++)
                {
                    code ^= ((keyIdentifier[i] & 0xff) << (i % 4));
                }
            }

			byte[] subKeyID = this.SubjectKeyIdentifier;
            if (subKeyID != null)
            {
                for (int i = 0; i != subKeyID.Length; i++)
                {
                    code ^= ((subKeyID[i] & 0xff) << (i % 4));
                }
            }

            if (this.SerialNumber != null)
            {
                code ^= this.SerialNumber.GetHashCode();
            }

            if (this.IssuerAsString != null)
            {
                code ^= this.IssuerAsString.GetHashCode();
            }

            return code;
        }

        public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			RecipientID id = obj as RecipientID;

			if (id == null)
				return false;

			return Arrays.AreSame(keyIdentifier, id.keyIdentifier)
				&& Arrays.AreSame(SubjectKeyIdentifier, id.SubjectKeyIdentifier)
				&& object.Equals(SerialNumber, id.SerialNumber)
				&& object.Equals(IssuerAsString, id.IssuerAsString);
        }
    }
}
