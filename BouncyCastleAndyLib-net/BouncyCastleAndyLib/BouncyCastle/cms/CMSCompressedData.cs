using System;
using System.IO;

//using ICSharpCode.SharpZipLib.Zip.Compression.Streams;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    /**
    * containing class for an CMS Compressed Data object
    */
    public class CmsCompressedData
    {
        internal ContentInfo contentInfo;

		public CmsCompressedData(
            byte[] compressedData)
            : this(CmsUtilities.ReadContentInfo(compressedData))
        {
        }

		public CmsCompressedData(
            Stream compressedDataStream)
            : this(CmsUtilities.ReadContentInfo(compressedDataStream))
        {
        }

		public CmsCompressedData(
            ContentInfo contentInfo)
        {
            this.contentInfo = contentInfo;
        }

		public byte[] GetContent()
        {
            CompressedData comData = CompressedData.GetInstance(contentInfo.Content);
            ContentInfo content = comData.EncapContentInfo;

			Asn1OctetString bytes = (Asn1OctetString) content.Content;

            //InflaterInputStream zIn = new InflaterInputStream(new MemoryStream(bytes.GetOctets(), false));
            MemoryStream bOut = new MemoryStream();

			byte[] buf = new byte[1024];
            //int len;

			try
            {
                //while ((len = zIn.Read(buf, 0, buf.Length)) > 0)
                //{
                //    bOut.Write(buf, 0, len);
                //}
            }
            catch (IOException e)
            {
                throw new CmsException("exception reading compressed stream.", e);
            }

			return bOut.ToArray();
        }

		/**
        * return the ASN.1 encoded representation of this object.
        */
        public byte[] GetEncoded()
        {
			return contentInfo.GetEncoded();
        }
    }
}
