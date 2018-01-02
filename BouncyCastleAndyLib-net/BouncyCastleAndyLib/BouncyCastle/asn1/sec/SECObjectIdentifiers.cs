using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;

namespace Org.BouncyCastle.Asn1.Sec
{
	public abstract class SecObjectIdentifiers
	{
		/**
		 *  EllipticCurve OBJECT IDENTIFIER ::= {
		 *        iso(1) identified-organization(3) certicom(132) curve(0)
		 *  }
		 */
		public static readonly DerObjectIdentifier EllipticCurve = new DerObjectIdentifier("1.3.132.0");

		public static readonly DerObjectIdentifier SecP192r1 = X9ObjectIdentifiers.Prime192v1;
		public static readonly DerObjectIdentifier SecT163k1 = new DerObjectIdentifier(EllipticCurve + ".1");
		public static readonly DerObjectIdentifier SecT163r1 = new DerObjectIdentifier(EllipticCurve + ".2");
		public static readonly DerObjectIdentifier SecT163r2 = new DerObjectIdentifier(EllipticCurve + ".15");
		public static readonly DerObjectIdentifier SecP224r1 = new DerObjectIdentifier(EllipticCurve + ".33");
		public static readonly DerObjectIdentifier SecT233k1 = new DerObjectIdentifier(EllipticCurve + ".26");
		public static readonly DerObjectIdentifier SecT233r1 = new DerObjectIdentifier(EllipticCurve + ".27");
		public static readonly DerObjectIdentifier SecP256r1 = X9ObjectIdentifiers.Prime256v1;
		public static readonly DerObjectIdentifier SecT283k1 = new DerObjectIdentifier(EllipticCurve + ".16");
		public static readonly DerObjectIdentifier SecT283r1 = new DerObjectIdentifier(EllipticCurve + ".17");
		public static readonly DerObjectIdentifier SecP384r1 = new DerObjectIdentifier(EllipticCurve + ".34");
		public static readonly DerObjectIdentifier SecT409k1 = new DerObjectIdentifier(EllipticCurve + ".36");
		public static readonly DerObjectIdentifier SecT409r1 = new DerObjectIdentifier(EllipticCurve + ".37");
		public static readonly DerObjectIdentifier SecP521r1 = new DerObjectIdentifier(EllipticCurve + ".35");
		public static readonly DerObjectIdentifier SecT571k1 = new DerObjectIdentifier(EllipticCurve + ".38");
		public static readonly DerObjectIdentifier SecT571r1 = new DerObjectIdentifier(EllipticCurve + ".39");
	}
}