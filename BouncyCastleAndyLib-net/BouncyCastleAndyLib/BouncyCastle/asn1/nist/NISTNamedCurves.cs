using System;
using System.Collections;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.Nist
{
	/**
	* Utility class for fetching curves using their NIST names as published in FIPS-PUB 186-2
	*/
	public sealed class NistNamedCurves
	{
		private NistNamedCurves()
		{
		}

		static readonly Hashtable objIds = new Hashtable();
		static readonly Hashtable curves = new Hashtable();
		static readonly Hashtable names = new Hashtable();

		private static X9ECParameters CheckedSecNamedCurve(
			string name)
		{
			X9ECParameters p = SecNamedCurves.GetByName(name);

			if (p == null)
				throw new ApplicationException("Failed SEC curve lookup");

			return p;
		}

		static NistNamedCurves()
		{
			objIds.Add("B-571", SecObjectIdentifiers.SecT571r1);
			objIds.Add("B-409", SecObjectIdentifiers.SecT409r1);
			objIds.Add("B-283", SecObjectIdentifiers.SecT283r1);
			objIds.Add("B-233", SecObjectIdentifiers.SecT233r1);
			objIds.Add("B-163", SecObjectIdentifiers.SecT163r2);
			objIds.Add("P-521", SecObjectIdentifiers.SecP521r1);
			objIds.Add("P-256", SecObjectIdentifiers.SecP256r1);
			objIds.Add("P-224", SecObjectIdentifiers.SecP224r1);
			objIds.Add("P-384", SecObjectIdentifiers.SecP384r1);

			names.Add(SecObjectIdentifiers.SecT571r1, "B-571");
			names.Add(SecObjectIdentifiers.SecT409r1, "B-409");
			names.Add(SecObjectIdentifiers.SecT283r1, "B-283");
			names.Add(SecObjectIdentifiers.SecT233r1, "B-233");
			names.Add(SecObjectIdentifiers.SecT163r2, "B-163");
			names.Add(SecObjectIdentifiers.SecP521r1, "P-521");
			names.Add(SecObjectIdentifiers.SecP256r1, "P-256");
			names.Add(SecObjectIdentifiers.SecP224r1, "P-224");
			names.Add(SecObjectIdentifiers.SecP384r1, "P-384");

			curves.Add(SecObjectIdentifiers.SecT571r1, CheckedSecNamedCurve("sect571r1"));
			curves.Add(SecObjectIdentifiers.SecT409r1, CheckedSecNamedCurve("sect409r1"));
			curves.Add(SecObjectIdentifiers.SecT283r1, CheckedSecNamedCurve("sect283r1"));
			curves.Add(SecObjectIdentifiers.SecT233r1, CheckedSecNamedCurve("sect233r1"));
			curves.Add(SecObjectIdentifiers.SecT163r2, CheckedSecNamedCurve("sect163r2"));
			curves.Add(SecObjectIdentifiers.SecP521r1, CheckedSecNamedCurve("secp521r1"));
			curves.Add(SecObjectIdentifiers.SecP256r1, CheckedSecNamedCurve("secp256r1"));
			curves.Add(SecObjectIdentifiers.SecP224r1, CheckedSecNamedCurve("secp224r1"));
			curves.Add(SecObjectIdentifiers.SecP384r1, CheckedSecNamedCurve("secp384r1"));
		}

		public static X9ECParameters GetByName(
			string name)
		{
			DerObjectIdentifier oid = (DerObjectIdentifier) objIds[name.ToUpper(CultureInfo.InvariantCulture)];

			if (oid != null)
			{
				return (X9ECParameters) curves[oid];
			}

			return null;
		}

		/**
		* return the X9ECParameters object for the named curve represented by
		* the passed in object identifier. Null if the curve isn't present.
		*
		* @param oid an object identifier representing a named curve, if present.
		*/
		public static X9ECParameters GetByOid(
			DerObjectIdentifier oid)
		{
			return (X9ECParameters) curves[oid];
		}

		/**
		* return the object identifier signified by the passed in name. Null
		* if there is no object identifier associated with name.
		*
		* @return the object identifier associated with name, if present.
		*/
		public static DerObjectIdentifier GetOid(
			string name)
		{
			return (DerObjectIdentifier) objIds[name];
		}

		/**
		* return the named curve name represented by the given object identifier.
		*/
		public static string GetName(
			DerObjectIdentifier  oid)
		{
			return (string) names[oid];
		}

		/**
		* returns an enumeration containing the name strings for curves
		* contained in this structure.
		*/
		public static IEnumerable Names
		{
			get { return new EnumerableProxy(objIds.Keys); }
		}
	}
}
