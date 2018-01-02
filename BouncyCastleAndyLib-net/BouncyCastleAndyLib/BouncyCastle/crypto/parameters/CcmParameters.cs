using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class CcmParameters
        : ICipherParameters
    {
        private readonly byte[] associatedText;
        private readonly byte[] nonce;
        private readonly KeyParameter key;
        private readonly int macSize;

        /**
         * Base constructor.
         *
         * @param key key to be used by underlying cipher
         * @param macSize macSize in bits
         * @param nonce nonce to be used
         * @param associatedText associated text, if any
         */
        public CcmParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText)
        {
            this.key = key;
            this.nonce = nonce;
            this.macSize = macSize;
            this.associatedText = associatedText;
        }

        public KeyParameter Key { get { return key; } }
        public int MacSize { get { return macSize; } }
        public byte[] GetAssociatedText() { return associatedText; }
        public byte[] GetNonce() { return nonce; }
    }
}
