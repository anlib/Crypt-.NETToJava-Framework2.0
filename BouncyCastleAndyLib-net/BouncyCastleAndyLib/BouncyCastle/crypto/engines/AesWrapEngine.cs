using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
	/// <remarks>
	/// An implementation of the AES Key Wrapper from the NIST Key Wrap Specification.
	/// <p>
	/// For further details see: <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
	/// </remarks>
    public class AesWrapEngine
		: IWrapper
    {
        private readonly IBlockCipher engine = new AesEngine();

		private KeyParameter	param;
        private bool			forWrapping;

        private byte[] iv = {
            (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6,
            (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6 };

		public void Init(
            bool				forWrapping,
            ICipherParameters	parameters)
        {
            this.forWrapping = forWrapping;

			if (parameters is KeyParameter)
			{
				this.param = (KeyParameter) parameters;
			}
			else if (parameters is ParametersWithIV)
			{
				ParametersWithIV pIV = (ParametersWithIV) parameters;
				byte[] iv = pIV.GetIV();

				if (iv.Length != 8)
					throw new ArgumentException("IV length not equal to 8", "parameters");

				this.iv = iv;
				this.param = (KeyParameter) pIV.Parameters;
			}
			else
			{
				// TODO Throw an exception for bad parameters?
			}
        }

		public string AlgorithmName
        {
            get { return "AES"; }
        }

		public byte[] Wrap(
            byte[]	input,
            int		inOff,
            int		length)
        {
            if (!forWrapping)
            {
                throw new InvalidOperationException("not set for wrapping");
            }

            int n = length / 8;

            if ((n * 8) != length)
            {
                throw new DataLengthException("wrap data must be a multiple of 8 bytes");
            }

            byte[] block = new byte[length + iv.Length];
            byte[] Buffer = new byte[8 + iv.Length];

            Array.Copy(iv, 0, block, 0, iv.Length);
            Array.Copy(input, 0, block, iv.Length, length);

            engine.Init(true, param);

            for (int j = 0; j != 6; j++)
            {
                for (int i = 1; i <= n; i++)
                {
                    Array.Copy(block, 0, Buffer, 0, iv.Length);
                    Array.Copy(block, 8 * i, Buffer, iv.Length, 8);
                    engine.ProcessBlock(Buffer, 0, Buffer, 0);

                    int t = n * j + i;
                    for (int k = 1; t != 0; k++)
                    {
                        byte v = (byte)t;

                        Buffer[iv.Length - k] ^= v;
                        t = (int) ((uint)t >> 8);
                    }

                    Array.Copy(Buffer, 0, block, 0, 8);
                    Array.Copy(Buffer, 8, block, 8 * i, 8);
                }
            }

            return block;
        }

        public byte[] Unwrap(
            byte[]	input,
            int		inOff,
            int		length)
        {
            if (forWrapping)
            {
                throw new InvalidOperationException("not set for unwrapping");
            }

            int n = length / 8;

            if ((n * 8) != length)
            {
                throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
            }

            byte[] block = new byte[length - iv.Length];
            byte[] a = new byte[iv.Length];
            byte[] Buffer = new byte[8 + iv.Length];

            Array.Copy(input, 0, a, 0, iv.Length);
            Array.Copy(input, iv.Length, block, 0, length - iv.Length);

            engine.Init(false, param);

            n = n - 1;

            for (int j = 5; j >= 0; j--)
            {
                for (int i = n; i >= 1; i--)
                {
                    Array.Copy(a, 0, Buffer, 0, iv.Length);
                    Array.Copy(block, 8 * (i - 1), Buffer, iv.Length, 8);

                    int t = n * j + i;
                    for (int k = 1; t != 0; k++)
                    {
                        byte v = (byte)t;

                        Buffer[iv.Length - k] ^= v;
                        t = (int) ((uint)t >> 8);
                    }

                    engine.ProcessBlock(Buffer, 0, Buffer, 0);
                    Array.Copy(Buffer, 0, a, 0, 8);
                    Array.Copy(Buffer, 8, block, 8 * (i - 1), 8);
                }
            }

			if (!Arrays.AreEqual(a, iv))
			{
				throw new InvalidCipherTextException("checksum failed");
			}

			return block;
        }
    }

}
