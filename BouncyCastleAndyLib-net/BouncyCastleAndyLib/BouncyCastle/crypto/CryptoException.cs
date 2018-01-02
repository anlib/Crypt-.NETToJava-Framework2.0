using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
    [SerializableAttribute]
    public abstract class CryptoException
		: Exception
    {
        protected CryptoException()
        {
        }

		protected CryptoException(
            string message)
			: base(message)
        {
        }

		protected CryptoException(
            string		message,
            Exception	exception)
			: base(message, exception)
        {
        }

		protected CryptoException(
            SerializationInfo	info,
            StreamingContext	context)
			: base(info, context)
        {
        }
    }
}
