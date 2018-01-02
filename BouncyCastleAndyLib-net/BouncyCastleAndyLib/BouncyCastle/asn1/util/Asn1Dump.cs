using Org.BouncyCastle.Utilities.Encoders;

using System;
using System.Collections;
using System.Text;

namespace Org.BouncyCastle.Asn1.Utilities
{
    public sealed class Asn1Dump
    {
        private Asn1Dump()
        {
        }

        private const string  TAB = "    ";

        /**
         * dump a Der object as a formatted string with indentation
         *
         * @param obj the Asn1Object to be dumped out.
         */
        private static string AsString(
            string		indent,
            Asn1Object	obj)
        {
            if (obj is Asn1Sequence)
            {
                StringBuilder    Buffer = new StringBuilder();
                string          tab = indent + TAB;

                Buffer.Append(indent);
                if (obj is DerSequence)
                {
                    Buffer.Append("DER Sequence");
                }
                else if (obj is BerSequence)
                {
                    Buffer.Append("BER Sequence");
                }
                else
                {
                    Buffer.Append("Sequence");
                }

                Buffer.Append(Environment.NewLine);

				foreach (object o in ((Asn1Sequence)obj))
				{
                    if (o == null || o.Equals(DerNull.Instance))
                    {
                        Buffer.Append(tab);
                        Buffer.Append("Null");
                        Buffer.Append(Environment.NewLine);
                    }
                    else if (o is Asn1Object)
                    {
                        Buffer.Append(AsString(tab, (Asn1Object)o));
                    }
                    else
                    {
                        Buffer.Append(AsString(tab, ((Asn1Encodable)o).ToAsn1Object()));
                    }
                }
                return Buffer.ToString();
            }
            else if (obj is DerTaggedObject)
            {
                StringBuilder Buffer = new StringBuilder();
                string tab = indent + TAB;

				Buffer.Append(indent);
                if (obj is BerTaggedObject)
                {
                    Buffer.Append("BER Tagged [");
                }
                else
                {
                    Buffer.Append("Tagged [");
                }

				DerTaggedObject o = (DerTaggedObject)obj;

				Buffer.Append(((int)o.TagNo).ToString());
                Buffer.Append(']');

				if (!o.IsExplicit())
                {
                    Buffer.Append(" IMPLICIT ");
                }

				Buffer.Append(Environment.NewLine);

				if (o.IsEmpty())
                {
                    Buffer.Append(tab);
                    Buffer.Append("EMPTY");
                    Buffer.Append(Environment.NewLine);
                }
                else
                {
                    Buffer.Append(AsString(tab, o.GetObject()));
                }

				return Buffer.ToString();
            }
            else if (obj is BerSet)
            {
                StringBuilder Buffer = new StringBuilder();
                string tab = indent + TAB;

				Buffer.Append(indent);
                Buffer.Append("BER Set");
                Buffer.Append(Environment.NewLine);

				foreach (object o in ((Asn1Set)obj))
				{
                    if (o == null)
                    {
                        Buffer.Append(tab);
                        Buffer.Append("Null");
                        Buffer.Append(Environment.NewLine);
                    }
                    else if (o is Asn1Object)
                    {
                        Buffer.Append(AsString(tab, (Asn1Object)o));
                    }
                    else
                    {
                        Buffer.Append(AsString(tab, ((Asn1Encodable)o).ToAsn1Object()));
                    }
                }
                return Buffer.ToString();
            }
            else if (obj is DerSet)
            {
                StringBuilder Buffer = new StringBuilder();
                string tab = indent + TAB;

				Buffer.Append(indent);
                Buffer.Append("DER Set");
                Buffer.Append(Environment.NewLine);

				foreach (object o in ((Asn1Set)obj))
				{
                    if (o == null)
                    {
                        Buffer.Append(tab);
                        Buffer.Append("Null");
                        Buffer.Append(Environment.NewLine);
                    }
                    else if (o is Asn1Object)
                    {
                        Buffer.Append(AsString(tab, (Asn1Object)o));
                    }
                    else
                    {
                        Buffer.Append(AsString(tab, ((Asn1Encodable)o).ToAsn1Object()));
                    }
                }

				return Buffer.ToString();
            }
            else if (obj is DerObjectIdentifier)
            {
                return indent + "ObjectIdentifier(" + ((DerObjectIdentifier)obj).Id + ")" + Environment.NewLine;
            }
            else if (obj is DerBoolean)
            {
                return indent + "Boolean(" + ((DerBoolean)obj).IsTrue + ")" + Environment.NewLine;
            }
            else if (obj is DerInteger)
            {
                return indent + "Integer(" + ((DerInteger)obj).Value + ")" + Environment.NewLine;
            }
            else if (obj is DerOctetString)
            {
                return indent + obj.ToString() + "[" + ((Asn1OctetString)obj).GetOctets().Length + "] " + Environment.NewLine;
            }
            else if (obj is DerIA5String)
            {
                return indent + "IA5String(" + ((DerIA5String)obj).GetString() + ") " + Environment.NewLine;
            }
            else if (obj is DerPrintableString)
            {
                return indent + "PrintableString(" + ((DerPrintableString)obj).GetString() + ") " + Environment.NewLine;
            }
            else if (obj is DerVisibleString)
            {
                return indent + "VisibleString(" + ((DerVisibleString)obj).GetString() + ") " + Environment.NewLine;
            }
            else if (obj is DerBmpString)
            {
                return indent + "BMPString(" + ((DerBmpString)obj).GetString() + ") " + Environment.NewLine;
            }
            else if (obj is DerT61String)
            {
                return indent + "T61String(" + ((DerT61String)obj).GetString() + ") " + Environment.NewLine;
            }
            else if (obj is DerUtcTime)
            {
                return indent + "UTCTime(" + ((DerUtcTime)obj).TimeString + ") " + Environment.NewLine;
            }
            else if (obj is DerUnknownTag)
            {
                return indent + "Unknown " + ((int)((DerUnknownTag)obj).Tag).ToString("X") + " "
                    + Encoding.ASCII.GetString(Hex.Encode(((DerUnknownTag)obj).GetData())) + Environment.NewLine;
            }
            else
            {
                return indent + obj.ToString() + Environment.NewLine;
            }
        }

        /**
         * dump out a Der object as a formatted string
         *
         * @param obj the Asn1Object to be dumped out.
         */
        public static string DumpAsString(
            object   obj)
        {
            if (obj is Asn1Object)
            {
                return AsString("", (Asn1Object)obj);
            }
            else if (obj is Asn1Encodable)
            {
                return AsString("", ((Asn1Encodable)obj).ToAsn1Object());
            }

            return "unknown object type " + obj.ToString();
        }
    }
}
