using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Utilities
{
	/**
	 * BigInteger utilities.
	 */
	public sealed class BigIntegers
	{
		private BigIntegers()
		{
		}

		/**
		* Return the passed in value as an unsigned byte array.
		*
		* @param value value to be converted.
		* @return a byte array without a leading zero byte if present in the signed encoding.
		*/
		public static byte[] AsUnsignedByteArray(
			BigInteger value)
		{
			byte[] bytes = value.ToByteArray();

			if (bytes[0] == 0)
			{
				byte[] tmp = new byte[bytes.Length - 1];

				Array.Copy(bytes, 1, tmp, 0, tmp.Length);

				return tmp;
			}

			return bytes;
		}
	}
}
