using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class RsaPrivateKeyStructure
        : Asn1Encodable
    {
        private BigInteger	modulus;
        private BigInteger	publicExponent;
        private BigInteger	privateExponent;
        private BigInteger	prime1;
        private BigInteger	prime2;
        private BigInteger	exponent1;
        private BigInteger	exponent2;
        private BigInteger	coefficient;

		public RsaPrivateKeyStructure(
            BigInteger  modulus,
            BigInteger  publicExponent,
            BigInteger  privateExponent,
            BigInteger  prime1,
            BigInteger  prime2,
            BigInteger  exponent1,
            BigInteger  exponent2,
            BigInteger  coefficient)
        {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
            this.privateExponent = privateExponent;
            this.prime1 = prime1;
            this.prime2 = prime2;
            this.exponent1 = exponent1;
            this.exponent2 = exponent2;
            this.coefficient = coefficient;
        }

		public RsaPrivateKeyStructure(
            Asn1Sequence seq)
        {
            IEnumerator e = seq.GetEnumerator();

			e.MoveNext();
            BigInteger version = ((DerInteger) e.Current).Value;
            if (version.IntValue != 0)
            {
                throw new ArgumentException("wrong version for RSA private key");
            }

			e.MoveNext();
            modulus = ((DerInteger)e.Current).Value;

			e.MoveNext();
            publicExponent = ((DerInteger)e.Current).Value;

			e.MoveNext();
            privateExponent = ((DerInteger)e.Current).Value;

			e.MoveNext();
            prime1 = ((DerInteger)e.Current).Value;

			e.MoveNext();
            prime2 = ((DerInteger)e.Current).Value;

			e.MoveNext();
            exponent1 = ((DerInteger)e.Current).Value;

			e.MoveNext();
            exponent2 = ((DerInteger)e.Current).Value;

			e.MoveNext();
            coefficient = ((DerInteger)e.Current).Value;
        }

		public BigInteger Modulus { get { return modulus; } }

		public BigInteger PublicExponent { get { return publicExponent; } }

		public BigInteger PrivateExponent { get { return privateExponent; } }

		public BigInteger Prime1 { get { return prime1; } }

		public BigInteger Prime2 { get { return prime2; } }

		public BigInteger Exponent1 { get { return exponent1; } }

		public BigInteger Exponent2 { get { return exponent2; } }

		public BigInteger Coefficient { get { return coefficient; } }

		/**
         * This outputs the key in Pkcs1v2 format.
         * <pre>
         *      RsaPrivateKey ::= Sequence {
         *                          version Version,
         *                          modulus Integer, -- n
         *                          publicExponent Integer, -- e
         *                          privateExponent Integer, -- d
         *                          prime1 Integer, -- p
         *                          prime2 Integer, -- q
         *                          exponent1 Integer, -- d mod (p-1)
         *                          exponent2 Integer, -- d mod (q-1)
         *                          coefficient Integer -- (inverse of q) mod p
         *                      }
         *
         *      Version ::= Integer
         * </pre>
         * <p>
         * This routine is written to output Pkcs1 version 0, private keys.
         */
        public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(
				new DerInteger(0), // version
				new DerInteger(Modulus),
				new DerInteger(PublicExponent),
				new DerInteger(PrivateExponent),
				new DerInteger(Prime1),
				new DerInteger(Prime2),
				new DerInteger(Exponent1),
				new DerInteger(Exponent2),
				new DerInteger(Coefficient));
        }
    }
}
