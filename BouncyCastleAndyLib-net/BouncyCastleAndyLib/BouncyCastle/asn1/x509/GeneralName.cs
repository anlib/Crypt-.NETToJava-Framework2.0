using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The GeneralName object.
     * <pre>
     * GeneralName ::= CHOICE {
     *      otherName                       [0]     OtherName,
     *      rfc822Name                      [1]     IA5String,
     *      dNSName                         [2]     IA5String,
     *      x400Address                     [3]     ORAddress,
     *      directoryName                   [4]     Name,
     *      ediPartyName                    [5]     EDIPartyName,
     *      uniformResourceIdentifier       [6]     IA5String,
     *      iPAddress                       [7]     OCTET STRING,
     *      registeredID                    [8]     OBJECT IDENTIFIER}
     *
     * OtherName ::= Sequence {
     *      type-id    OBJECT IDENTIFIER,
     *      value      [0] EXPLICIT ANY DEFINED BY type-id }
     *
     * EDIPartyName ::= Sequence {
     *      nameAssigner            [0]     DirectoryString OPTIONAL,
     *      partyName               [1]     DirectoryString }
     * </pre>
     */
    public class GeneralName
        : Asn1Encodable
    {
        public const int OtherName					= 0;
        public const int Rfc822Name					= 1;
        public const int DnsName					= 2;
        public const int X400Address				= 3;
        public const int DirectoryName				= 4;
        public const int EdiPartyName				= 5;
        public const int UniformResourceIdentifier	= 6;
        public const int IPAddress					= 7;
        public const int RegisteredID				= 8;

		internal readonly Asn1Encodable	obj;
        internal readonly int			tag;

		public GeneralName(
            X509Name directoryName)
        {
            this.obj = directoryName;
            this.tag = 4;
        }

		/**
         * When the subjectAltName extension contains an Internet mail address,
         * the address MUST be included as an rfc822Name. The format of an
         * rfc822Name is an "addr-spec" as defined in RFC 822 [RFC 822].
         *
         * When the subjectAltName extension contains a domain name service
         * label, the domain name MUST be stored in the dNSName (an IA5String).
         * The name MUST be in the "preferred name syntax," as specified by RFC
         * 1034 [RFC 1034].
         *
         * When the subjectAltName extension contains a URI, the name MUST be
         * stored in the uniformResourceIdentifier (an IA5String). The name MUST
         * be a non-relative URL, and MUST follow the URL syntax and encoding
         * rules specified in [RFC 1738].  The name must include both a scheme
         * (e.g., "http" or "ftp") and a scheme-specific-part.  The scheme-
         * specific-part must include a fully qualified domain name or IP
         * address as the host.
         *
         * When the subjectAltName extension contains a iPAddress, the address
         * MUST be stored in the octet string in "network byte order," as
         * specified in RFC 791 [RFC 791]. The least significant bit (LSB) of
         * each octet is the LSB of the corresponding byte in the network
         * address. For IP Version 4, as specified in RFC 791, the octet string
         * MUST contain exactly four octets.  For IP Version 6, as specified in
         * RFC 1883, the octet string MUST contain exactly sixteen octets [RFC
         * 1883].
         */
        public GeneralName(
            Asn1Object	name,
			int			tag)
        {
            this.obj = name;
            this.tag = tag;
        }

		public GeneralName(
            int				tag,
            Asn1Encodable	name)
        {
            this.obj = name;
            this.tag = tag;
        }

		/**
         * Create a General name for the given tag from the passed in string.
         *
         * @param tag tag number
         * @param name string representation of name
         */
        public GeneralName(
            int		tag,
            string	name)
        {
            if (tag == Rfc822Name || tag == DnsName || tag == UniformResourceIdentifier)
            {
                this.tag = tag;
                this.obj = new Asn1.DerIA5String(name);
            }
            else if (tag == RegisteredID)
            {
                this.tag = tag;
                this.obj = new DerObjectIdentifier(name);
            }
            else
            {
                throw new ArgumentException("can't process string for tag: " + tag);
            }
        }

        public static GeneralName GetInstance(
            object obj)
        {
            if (obj == null || obj is GeneralName)
            {
                return (GeneralName) obj;
            }

            if (obj is Asn1TaggedObject)
            {
                Asn1TaggedObject	tagObj = (Asn1TaggedObject) obj;
                int                 tag = tagObj.TagNo;

				switch (tag)
                {
					case 0:
						return new GeneralName(tagObj.GetObject(), tag);
					case 1:
						return new GeneralName(DerIA5String.GetInstance(tagObj, false), tag);
					case 2:
						return new GeneralName(DerIA5String.GetInstance(tagObj, false), tag);
					case 3:
						throw new ArgumentException("unknown tag: " + tag);
					case 4:
						return new GeneralName(tagObj.GetObject(), tag);
					case 5:
						return new GeneralName(tagObj.GetObject(), tag);
					case 6:
						return new GeneralName(DerIA5String.GetInstance(tagObj, false), tag);
					case 7:
						return new GeneralName(Asn1OctetString.GetInstance(tagObj, false), tag);
					case 8:
						return new GeneralName(DerObjectIdentifier.GetInstance(tagObj, false), tag);
                }
            }

			throw new ArgumentException("unknown object in GetInstance");
        }

		public static GeneralName GetInstance(
            Asn1TaggedObject	tagObj,
            bool				explicitly)
        {
            return GeneralName.GetInstance(Asn1TaggedObject.GetInstance(tagObj, explicitly));
        }

		public int TagNo
		{
			get { return tag; }
		}

		public Asn1Encodable Name
		{
			get { return obj; }
		}

		public override Asn1Object ToAsn1Object()
        {
			// Explicitly tagged if DirectoryName
			return new DerTaggedObject(tag == 4, tag, obj);
        }
    }
}
