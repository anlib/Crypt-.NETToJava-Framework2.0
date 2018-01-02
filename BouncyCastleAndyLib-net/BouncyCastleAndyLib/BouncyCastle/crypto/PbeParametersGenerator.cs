using System;
using System.Text;

namespace Org.BouncyCastle.Crypto
{
    /**
     * super class for all Password Based Encyrption (Pbe) parameter generator classes.
     */
    public abstract class PbeParametersGenerator
    {
        internal byte[]  password;
        internal byte[]  salt;
        internal int     iterationCount;

        /**
         * base constructor.
         */
        internal PbeParametersGenerator()
        {
        }

        /**
         * initialise the Pbe generator.
         *
         * @param password the password converted into bytes (see below).
         * @param salt the salt to be mixed with the password.
         * @param iterationCount the number of iterations the "mixing" function
         * is to be applied for.
         */
        public void Init(
            byte[]  password,
            byte[]  salt,
            int     iterationCount)
        {
			if (password == null)
				throw new ArgumentNullException("password");
			if (salt == null)
				throw new ArgumentNullException("salt");

            this.password = (byte[]) password.Clone();
            this.salt = (byte[]) salt.Clone();
            this.iterationCount = iterationCount;
        }

        /**
         * return the password byte array.
         *
         * @return the password byte array.
         */
        public byte[] GetPassword()
        {
            return (byte[]) password.Clone();
        }

        /**
         * return the salt byte array.
         *
         * @return the salt byte array.
         */
        public byte[] GetSalt()
        {
            return (byte[]) salt.Clone();
        }

		/**
         * return the iteration count.
         *
         * @return the iteration count.
         */
        public int IterationCount
        {
			get { return iterationCount; }
        }

		/**
         * Generate derived parameters for a key of length keySize.
         *
         * @param keySize the length, in bits, of the key required.
         * @return a parameters object representing a key.
         */
        public abstract ICipherParameters GenerateDerivedParameters(int keySize);

        /**
         * Generate derived parameters for a key of length keySize, and
         * an initialisation vector (IV) of length ivSize.
         *
         * @param keySize the length, in bits, of the key required.
         * @param ivSize the length, in bits, of the iv required.
         * @return a parameters object representing a key and an IV.
         */
        public abstract ICipherParameters GenerateDerivedParameters(int keySize, int ivSize);

        /**
         * Generate derived parameters for a key of length keySize, specifically
         * for use with a MAC.
         *
         * @param keySize the length, in bits, of the key required.
         * @return a parameters object representing a key.
         */
        public abstract ICipherParameters GenerateDerivedMacParameters(int keySize);

        /**
         * converts a password to a byte array according to the scheme in
         * Pkcs5 (ascii, no padding)
         *
         * @param password a character array reqpresenting the password.
         * @return a byte array representing the password.
         */
        public static byte[] Pkcs5PasswordToBytes(
            char[] password)
        {
			return Encoding.ASCII.GetBytes(password);
        }

		public static byte[] Pkcs5PasswordToBytes(
			string password)
		{
			return Encoding.ASCII.GetBytes(password);
		}

		/**
         * converts a password to a byte array according to the scheme in
         * Pkcs12 (unicode, big endian, 2 zero pad bytes at the end).
         *
         * @param password a character array representing the password.
         * @return a byte array representing the password.
         */
		public static byte[] Pkcs12PasswordToBytes(
			char[] password)
		{
			return Pkcs12PasswordToBytes(password, false);
		}

		public static byte[] Pkcs12PasswordToBytes(
            char[]	password,
			bool	wrongPkcs12Zero)
        {
			if (password.Length < 1)
			{
				return new byte[wrongPkcs12Zero ? 2 : 0];
			}

			// +1 for extra 2 pad bytes.
            byte[] bytes = new byte[(password.Length + 1) * 2];

			Encoding.BigEndianUnicode.GetBytes(password, 0, password.Length, bytes, 0);

			return bytes;
        }
    }
}
