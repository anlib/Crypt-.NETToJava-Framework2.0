using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class PrivateKeyInfo
        : Asn1Encodable
    {
        private readonly Asn1Object privKey;
        private readonly AlgorithmIdentifier algID;

		public static PrivateKeyInfo GetInstance(
            object obj)
        {
            if (obj is PrivateKeyInfo || obj == null)
            {
                return (PrivateKeyInfo) obj;
            }

			if (obj is Asn1Sequence)
            {
                return new PrivateKeyInfo((Asn1Sequence) obj);
            }

			throw new ArgumentException("unknown object in factory");
        }

		public PrivateKeyInfo(
            AlgorithmIdentifier	algID,
            Asn1Object			privateKey)
        {
            this.privKey = privateKey;
            this.algID = algID;
        }

		private PrivateKeyInfo(
            Asn1Sequence seq)
        {
            IEnumerator e = seq.GetEnumerator();

			e.MoveNext();
            BigInteger version = ((DerInteger) e.Current).Value;
            if (version.IntValue != 0)
            {
                throw new ArgumentException("wrong version for private key info");
            }

			e.MoveNext();
            algID = AlgorithmIdentifier.GetInstance(e.Current);

			e.MoveNext();
			Asn1OctetString data = (Asn1OctetString) e.Current;

			try
            {
				privKey = Asn1Object.FromByteArray(data.GetOctets());
            }
            catch (IOException)
            {
				throw new ArgumentException("Error recoverying private key from sequence");
            }
        }

		public AlgorithmIdentifier AlgorithmID
		{
			get { return algID; }
		}

		public Asn1Object PrivateKey
		{
			get { return privKey; }
		}

		/**
         * write out an RSA private key with it's asscociated information
         * as described in Pkcs8.
         * <pre>
         *      PrivateKeyInfo ::= Sequence {
         *                              version Version,
         *                              privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
         *                              privateKey PrivateKey,
         *                              attributes [0] IMPLICIT Attributes OPTIONAL
         *                          }
         *      Version ::= Integer {v1(0)} (v1,...)
         *
         *      PrivateKey ::= OCTET STRING
         *
         *      Attributes ::= Set OF Attr
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(
				new DerInteger(0),
				algID,
				new DerOctetString(privKey));
        }
    }
}
