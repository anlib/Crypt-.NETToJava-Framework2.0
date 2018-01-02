using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Security
{
    [SerializableAttribute]
    public class SecurityUtilityException : Exception
    {
        /**
            * base constructor.
            */
        public SecurityUtilityException()
        {
        }

        /**
         * create a SecurityUtilityException with the given message.
         *
         * @param message the message to be carried with the exception.
         */
        public SecurityUtilityException(
            string  message) : base(message)
        {
        }

		public SecurityUtilityException(
            string message,
            Exception exception) : base(message, exception)
        {

        }

        protected SecurityUtilityException(
            SerializationInfo info,
            StreamingContext context) : base(info, context)
        {
        }

    }

}
