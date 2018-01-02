using System;
using System.Collections;
using System.IO;

//using ICSharpCode.SharpZipLib.Zip.Compression.Streams;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /**
    * General class for generating a compressed CMS message.
    * <p>
    * A simple example of usage.
    * <p>
    * <pre>
    *      CMSCompressedDataGenerator  fact = new CMSCompressedDataGenerator();
    *
    *      CMSCompressedData           data = fact.Generate(content, algorithm);
    * </pre>
    */
    public class CmsCompressedDataGenerator
    {
        public const string ZLib = "1.2.840.113549.1.9.16.3.8";

		public CmsCompressedDataGenerator()
        {
        }

		/**
        * Generate an object that contains an CMS Compressed Data
        */
        public CmsCompressedData Generate(
            CmsProcessable	content,
            string			compressionOid)
        {
            AlgorithmIdentifier comAlgId;
            Asn1OctetString comOcts;

            try
            {
                MemoryStream bOut = new MemoryStream();
                //DeflaterOutputStream zOut = null;

                //content.Write(zOut);

                //zOut.Close();

				comAlgId = new AlgorithmIdentifier(
					new DerObjectIdentifier(compressionOid),
					null);

				comOcts = new BerOctetString(bOut.ToArray());
            }
            catch (IOException e)
            {
                throw new CmsException("exception encoding data.", e);
            }

            ContentInfo comContent = new ContentInfo(CmsObjectIdentifiers.Data, comOcts);
            ContentInfo contentInfo = new ContentInfo(
                CmsObjectIdentifiers.CompressedData,
                new CompressedData(comAlgId, comContent));

			return new CmsCompressedData(contentInfo);
        }
    }
}
