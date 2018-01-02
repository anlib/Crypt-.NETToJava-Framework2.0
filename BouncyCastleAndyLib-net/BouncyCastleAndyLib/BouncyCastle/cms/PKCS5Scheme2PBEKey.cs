using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Cms
{
	public class Pkcs5Scheme2PbeKey
		: CmsPbeKey
	{
		public Pkcs5Scheme2PbeKey(
//			char[]	password,
			string	password,
			byte[]	salt,
			int		iterationCount)
			: base(password, salt, iterationCount)
		{
		}

		internal override byte[] GetEncoded(
			string algorithmOid)
		{
			Pkcs5S2ParametersGenerator gen = new Pkcs5S2ParametersGenerator();

			gen.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(this.Password), this.GetSalt(), this.IterationCount);

			return ((KeyParameter)gen.GenerateDerivedParameters(CmsEnvelopedHelper.Instance.GetKeySize(algorithmOid))).GetKey();
		}
	}
}
