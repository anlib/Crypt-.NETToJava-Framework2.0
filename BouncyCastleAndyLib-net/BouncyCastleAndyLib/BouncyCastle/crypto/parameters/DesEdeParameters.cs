using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class DesEdeParameters
		: DesParameters
    {
        /*
        * DES-EDE Key length in bytes.
        */
        public const int DesEdeKeyLength = 24;

		public DesEdeParameters(
            byte[] key)
			: base(key)
        {
            if (IsWeakKey(key))
            {
                throw new ArgumentException("attempt to create weak DESede key");
            }
        }

		/**
         * return true if the passed in key is a DES-EDE weak key.
         *
         * @param key bytes making up the key
         * @param offset offset into the byte array the key starts at
         * @param length number of bytes making up the key
         */
        public static bool IsWeakKey(
            byte[]  key,
            int     offset,
            int     length)
        {
            for (int i = offset; i < length; i += DesKeyLength)
            {
                if (DesParameters.IsWeakKey(key, i))
                {
                    return true;
                }
            }

            return false;
        }

        /**
         * return true if the passed in key is a DES-EDE weak key.
         *
         * @param key bytes making up the key
         * @param offset offset into the byte array the key starts at
         */
        public static new bool IsWeakKey(
            byte[]	key,
            int		offset)
        {
            return IsWeakKey(key, offset, key.Length - offset);
        }

		public static new bool IsWeakKey(
			byte[] key)
		{
			return IsWeakKey(key, 0, key.Length);
		}
    }
}
