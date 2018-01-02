using System;
using System.Collections;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{
	/**
	 * This extension may contain further X.500 attributes of the subject. See also
	 * RFC 3039.
	 *
	 * <pre>
	 *     SubjectDirectoryAttributes ::= Attributes
	 *     Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
	 *     Attribute ::= SEQUENCE
	 *     {
	 *       type AttributeType
	 *       values SET OF AttributeValue
	 *     }
	 *
	 *     AttributeType ::= OBJECT IDENTIFIER
	 *     AttributeValue ::= ANY DEFINED BY AttributeType
	 * </pre>
	 *
	 * @see Org.BouncyCastle.asn1.x509.X509Name for AttributeType ObjectIdentifiers.
	 */
	public class SubjectDirectoryAttributes
		: Asn1Encodable
	{
		private readonly ArrayList attributes = new ArrayList();

		public static SubjectDirectoryAttributes GetInstance(
			object obj)
		{
			if (obj == null || obj is SubjectDirectoryAttributes)
			{
				return (SubjectDirectoryAttributes) obj;
			}

			if (obj is Asn1Sequence)
			{
				return new SubjectDirectoryAttributes((Asn1Sequence) obj);
			}

			throw new ArgumentException("illegal object in GetInstance: " + obj.GetType().Name);
		}

		/**
		 * Constructor from Asn1Sequence.
		 *
		 * The sequence is of type SubjectDirectoryAttributes:
		 *
		 * <pre>
		 *      SubjectDirectoryAttributes ::= Attributes
		 *      Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
		 *      Attribute ::= SEQUENCE
		 *      {
		 *        type AttributeType
		 *        values SET OF AttributeValue
		 *      }
		 *
		 *      AttributeType ::= OBJECT IDENTIFIER
		 *      AttributeValue ::= ANY DEFINED BY AttributeType
		 * </pre>
		 *
		 * @param seq
		 *            The ASN.1 sequence.
		 */
		private SubjectDirectoryAttributes(
			Asn1Sequence seq)
		{
			foreach (object o in seq)
			{
				Asn1Sequence s = Asn1Sequence.GetInstance(o);
				attributes.Add(AttributeX509.GetInstance(s));
			}
		}

		/**
		 * Constructor from a vector of attributes.
		 *
		 * The vector consists of attributes of type {@link Attribute Attribute}
		 *
		 * @param attributes
		 *            The attributes.
		 *
		 */
		public SubjectDirectoryAttributes(
			ArrayList attributes)
		{
			this.attributes.AddRange(attributes);
		}

		/**
		 * Produce an object suitable for an Asn1OutputStream.
		 *
		 * Returns:
		 *
		 * <pre>
		 *      SubjectDirectoryAttributes ::= Attributes
		 *      Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
		 *      Attribute ::= SEQUENCE
		 *      {
		 *        type AttributeType
		 *        values SET OF AttributeValue
		 *      }
		 *
		 *      AttributeType ::= OBJECT IDENTIFIER
		 *      AttributeValue ::= ANY DEFINED BY AttributeType
		 * </pre>
		 *
		 * @return a DERObject
		 */
		public override Asn1Object ToAsn1Object()
		{
			AttributeX509[] v = (AttributeX509[]) attributes.ToArray(typeof(AttributeX509));

			return new DerSequence(v);
		}

		/**
		 * @return Returns the attributes.
		 */
		public IEnumerable Attributes
		{
			get { return new EnumerableProxy(attributes); }
		}
	}
}
