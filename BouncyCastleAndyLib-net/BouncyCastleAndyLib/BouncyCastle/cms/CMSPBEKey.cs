using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

//import javax.crypto.interfaces.PBEKey;

namespace Org.BouncyCastle.Cms
{
	public abstract class CmsPbeKey
		// TODO Create an equivalent interface somewhere?
		//	: PBEKey
		:	ICipherParameters
	{
//		private readonly char[] password;
		private readonly string	password;
		private readonly byte[]	salt;
		private readonly int	iterationCount;

		public CmsPbeKey(
//			char[]	password,
			string	password,
			byte[]	salt,
			int		iterationCount)
		{
			this.password = password;
			this.salt = Arrays.Clone(salt);
			this.iterationCount = iterationCount;
		}

		public string Password
		{
			get { return password; }
		}

		public byte[] GetSalt()
		{
			return Arrays.Clone(salt);
		}

		public int IterationCount
		{
			get { return iterationCount; }
		}

		public string Algorithm
		{
			get { return "PKCS5S2"; }
		}

		public string Format
		{
			get { return "RAW"; }
		}

		public byte[] GetEncoded()
		{
			return null;
		}

		internal abstract byte[] GetEncoded(string algorithmOid);
	}
}
