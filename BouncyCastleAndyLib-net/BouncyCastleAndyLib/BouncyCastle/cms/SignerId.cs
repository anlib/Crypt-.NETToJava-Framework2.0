using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    /**
    * a basic index for a signer.
    */
    public class SignerID
        : X509CertStoreSelector
    {
        public override int GetHashCode()
        {
            int code = 0;

			if (this.SerialNumber != null)
            {
                code ^= this.SerialNumber.GetHashCode();
            }

            if (this.IssuerAsString != null)
            {
                code ^= this.IssuerAsString.GetHashCode();
            }

            byte[] subKeyID = this.SubjectKeyIdentifier;
            if (subKeyID != null)
            {
                for (int i = 0; i != subKeyID.Length; i++)
                {
                    code ^= ((subKeyID[i]) & 0xff) << (i % 4);
                }
            }

            return code;
        }

        public override bool Equals(
            object obj)
        {
			if (obj == this)
				return false;

			SignerID id = obj as SignerID;

			if (id == null)
				return false;

			return object.Equals(SerialNumber, id.SerialNumber)
				&& object.Equals(IssuerAsString, id.IssuerAsString)
				&& Arrays.AreSame(SubjectKeyIdentifier, id.SubjectKeyIdentifier);
        }
    }
}
