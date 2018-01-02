using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crypto
{
    /**
     * this exception is thrown whenever we find something we don't expect in a
     * message.
     */
    [SerializableAttribute]
    public class InvalidCipherTextException
		: CryptoException
    {
		/**
		* base constructor.
		*/
        public InvalidCipherTextException()
        {
        }

		/**
         * create a InvalidCipherTextException with the given message.
         *
         * @param message the message to be carried with the exception.
         */
        public InvalidCipherTextException(
            string message)
			: base(message)
        {
        }

		public InvalidCipherTextException(
            string		message,
            Exception	exception)
			: base(message, exception)
        {
        }

        protected InvalidCipherTextException(
            SerializationInfo	info,
            StreamingContext	context)
			: base(info, context)
        {
        }
    }
}
