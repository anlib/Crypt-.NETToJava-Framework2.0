using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Modes
{
    /**
    * Implements the Counter with Cipher Block Chaining mode (CCM) detailed in
    * NIST Special Publication 800-38C.
    * <p>
    * <b>Note</b>: this mode is a packet mode - it needs all the data up front.
    */
    public class CcmBlockCipher
    {
        private const int blockSize = 16;

        private readonly IBlockCipher cipher;
        private readonly byte[] macBlock;
        private bool forEncryption;
        private CcmParameters parameters;

        /**
        * Basic constructor.
        *
        * @param cipher the block cipher to be used.
        */
        public CcmBlockCipher(IBlockCipher cipher)
        {
            this.cipher = cipher;
            this.macBlock = new byte[blockSize];

            if (cipher.GetBlockSize() != blockSize)
            {
                throw new ArgumentException("cipher required with a block size of " + blockSize + ".");
            }
        }

        /**
        * return the underlying block cipher that we are wrapping.
        *
        * @return the underlying block cipher that we are wrapping.
        */
        public IBlockCipher GetUnderlyingCipher()
        {
            return cipher;
        }


        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            if (!(parameters is CcmParameters))
            {
                throw new ArgumentException("parameters need to be CCMParameters");
            }

            this.forEncryption = forEncryption;
            this.parameters = (CcmParameters)parameters;
        }

		public string AlgorithmName
        {
            get { return cipher.AlgorithmName + "/CCM"; }
        }

        /**
        * Returns a byte array containing the mac calculated as part of the
        * last encrypt or decrypt operation.
        *
        * @return the last mac calculated.
        */
        public byte[] GetMac()
        {
            byte[] mac = new byte[parameters.MacSize / 8];

            Array.Copy(macBlock, 0, mac, 0, mac.Length);

            return mac;
        }

        public byte[] ProcessPacket(byte[] input, int inOff, int inLen)
        {
            if (parameters == null)
            {
                throw new InvalidOperationException("CCM cipher unitialized.");
            }

            IBlockCipher ctrCipher = new SicBlockCipher(cipher);
            byte[] iv = new byte[blockSize];
            byte[] nonce = parameters.GetNonce();
            int    macSize = parameters.MacSize / 8;
            byte[] output;

            iv[0] = (byte)(((15 - nonce.Length) - 1) & 0x7);

            Array.Copy(nonce, 0, iv, 1, nonce.Length);

            ctrCipher.Init(forEncryption, new ParametersWithIV(parameters.Key, iv));

            if (forEncryption)
            {
                int index = inOff;
                int outOff = 0;

                output = new byte[inLen + macSize];

                calculateMac(input, inOff, inLen, macBlock);

                ctrCipher.ProcessBlock(macBlock, 0, macBlock, 0);   // S0

                while (index < inLen - blockSize)                   // S1...
                {
                    ctrCipher.ProcessBlock(input, index, output, outOff);
                    outOff += blockSize;
                    index += blockSize;
                }

                byte[] block = new byte[blockSize];

                Array.Copy(input, index, block, 0, inLen - index);

                ctrCipher.ProcessBlock(block, 0, block, 0);

                Array.Copy(block, 0, output, outOff, inLen - index);

                outOff += inLen - index;

                Array.Copy(macBlock, 0, output, outOff, output.Length - outOff);
            }
            else
            {
                int index = inOff;
                int outOff = 0;

                output = new byte[inLen - macSize];

                Array.Copy(input, inOff + inLen - macSize, macBlock, 0, macSize);

                ctrCipher.ProcessBlock(macBlock, 0, macBlock, 0);

                for (int i = macSize; i != macBlock.Length; i++)
                {
                    macBlock[i] = 0;
                }

                while (outOff < output.Length - blockSize)
                {
                    ctrCipher.ProcessBlock(input, index, output, outOff);
                    outOff += blockSize;
                    index += blockSize;
                }

                byte[] block = new byte[blockSize];

                Array.Copy(input, index, block, 0, output.Length - outOff);

                ctrCipher.ProcessBlock(block, 0, block, 0);

                Array.Copy(block, 0, output, outOff, output.Length - outOff);

                byte[] calculatedMacBlock = new byte[blockSize];

                calculateMac(output, 0, output.Length, calculatedMacBlock);

                if (!areEqual(macBlock, calculatedMacBlock))
                {
                    throw new InvalidCipherTextException("mac check in CCM failed");
                }
            }

            return output;
        }

        private int calculateMac(byte[] data, int dataOff, int dataLen, byte[] macBlock)
        {
            IMac cMac = new CbcBlockCipherMac(cipher, parameters.MacSize);

            byte[] nonce = parameters.GetNonce();
            byte[] associatedText = parameters.GetAssociatedText();

            cMac.Init(parameters.Key);

            //
            // build b0
            //
            byte[] b0 = new byte[16];

            if (associatedText != null && associatedText.Length != 0)
            {
                b0[0] |= 0x40;
            }

            b0[0] |= (byte)((((cMac.GetMacSize() - 2) / 2) & 0x7) << 3);

            b0[0] |= (byte)(((15 - nonce.Length) - 1) & 0x7);

            Array.Copy(nonce, 0, b0, 1, nonce.Length);

            int q = dataLen;
            int count = 1;
            while (q > 0)
            {
                b0[b0.Length - count] = (byte)(q & 0xff);
                q >>= 8;
                count++;
            }

            cMac.BlockUpdate(b0, 0, b0.Length);

            //
            // process associated text
            //
            if (associatedText != null)
            {
                int extra;

                if (associatedText.Length < ((1 << 16) - (1 << 8)))
                {
                    cMac.Update((byte)(associatedText.Length >> 8));
                    cMac.Update((byte)associatedText.Length);

                    extra = 2;
                }
                else // can't go any higher than 2^32
                {
                    cMac.Update((byte)0xff);
                    cMac.Update((byte)0xfe);
                    cMac.Update((byte)(associatedText.Length >> 24));
                    cMac.Update((byte)(associatedText.Length >> 16));
                    cMac.Update((byte)(associatedText.Length >> 8));
                    cMac.Update((byte)associatedText.Length);

                    extra = 6;
                }

                cMac.BlockUpdate(associatedText, 0, associatedText.Length);

                extra = (extra + associatedText.Length) % 16;
                if (extra != 0)
                {
                    for (int i = 0; i != 16 - extra; i++)
                    {
                        cMac.Update((byte)0x00);
                    }
                }
            }

            //
            // add the text
            //
            cMac.BlockUpdate(data, dataOff, dataLen);

            return cMac.DoFinal(macBlock, 0);
        }

        /**
        * compare two byte arrays.
        */
        private static bool areEqual(
            byte[]    a,
            byte[]    b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            for (int i = 0; i != b.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
