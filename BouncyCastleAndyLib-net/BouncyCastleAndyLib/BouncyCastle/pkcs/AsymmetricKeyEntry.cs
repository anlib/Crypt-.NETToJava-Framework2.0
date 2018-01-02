using System;
using System.IO;
using System.Collections;
using System.Text;

using Org.BouncyCastle.Crypto.Parameters;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.Oiw;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkcs
{
    public class AsymmetricKeyEntry
        : Pkcs12Entry
    {
        private readonly AsymmetricKeyParameter key;

		public AsymmetricKeyEntry(
            AsymmetricKeyParameter key)
			: base(new Hashtable())
        {
            this.key = key;
        }

		public AsymmetricKeyEntry(
            AsymmetricKeyParameter	key,
            Hashtable				attributes)
			: base(attributes)
        {
            this.key = key;
        }

		public AsymmetricKeyParameter Key
        {
            get { return this.key; }
        }
    }
}
