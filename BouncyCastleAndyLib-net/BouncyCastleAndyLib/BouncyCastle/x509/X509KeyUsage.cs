using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.X509
{
	/**
	 * A holding class for constructing an X509 Key Usage extension.
	 *
	 * <pre>
	 *    id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
	 *
	 *    KeyUsage ::= BIT STRING {
	 *         digitalSignature        (0),
	 *         nonRepudiation          (1),
	 *         keyEncipherment         (2),
	 *         dataEncipherment        (3),
	 *         keyAgreement            (4),
	 *         keyCertSign             (5),
	 *         cRLSign                 (6),
	 *         encipherOnly            (7),
	 *         decipherOnly            (8) }
	 * </pre>
	 */
	public class X509KeyUsage
		: Asn1Encodable
	{
		public static readonly int DigitalSignature = 1 << 7;
		public static readonly int NonRepudiation   = 1 << 6;
		public static readonly int KeyEncipherment  = 1 << 5;
		public static readonly int DataEncipherment = 1 << 4;
		public static readonly int KeyAgreement     = 1 << 3;
		public static readonly int KeyCertSign      = 1 << 2;
		public static readonly int CrlSign          = 1 << 1;
		public static readonly int EncipherOnly     = 1 << 0;
		public static readonly int DecipherOnly     = 1 << 15;

		private readonly int usage;

		/**
		 * Basic constructor.
		 *
		 * @param usage - the bitwise OR of the Key Usage flags giving the
		 * allowed uses for the key.
		 * e.g. (X509KeyUsage.keyEncipherment | X509KeyUsage.dataEncipherment)
		 */
		public X509KeyUsage(
			int usage)
		{
			this.usage = usage;
		}

		public override Asn1Object ToAsn1Object()
		{
			return new KeyUsage(usage);
		}
	}
}
