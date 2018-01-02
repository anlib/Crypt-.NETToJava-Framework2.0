using System;
using System.IO;

namespace Org.BouncyCastle.Cms
{
	/**
	* a holding class for a file of data to be processed.
	*/
	public class CmsProcessableFile
		: CmsProcessable
	{
		private const int DEFAULT_BUF_SIZE = 32 * 1024;

		private readonly FileInfo   _file;
		private readonly byte[] _buf;

		public CmsProcessableFile(
			FileInfo file)
			: this(file, DEFAULT_BUF_SIZE)
		{
		}

		public CmsProcessableFile(
			FileInfo file,
			int  bufSize)
		{
			_file = file;
			_buf = new byte[bufSize];
		}

		public void Write(Stream zOut)
		{
			FileStream     fIn = _file.Open(FileMode.Open);
			int                 len;

			while ((len = fIn.Read(_buf, 0, _buf.Length)) > 0)
			{
				zOut.Write(_buf, 0, len);
			}

			fIn.Close();
		}

		/**
		* Return the file handle.
		*/
		public object GetContent()
		{
			return _file;
		}
	}
}
