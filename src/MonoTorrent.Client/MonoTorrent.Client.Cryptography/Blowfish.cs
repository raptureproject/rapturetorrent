using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace MonoTorrent.Client.Cryptography
{
    internal abstract class Blowfish : SymmetricAlgorithm
    {
        private static readonly KeySizes[] s_legalBlockSizes = new KeySizes[] { new KeySizes (64, 64, 0) };
        private static readonly KeySizes[] s_legalKeySizes = new KeySizes[] { new KeySizes (32, 448, 8) };

        protected Blowfish ()
        {
            LegalBlockSizesValue = (KeySizes[]) s_legalBlockSizes.Clone ();
            LegalKeySizesValue = (KeySizes[]) s_legalKeySizes.Clone ();

            BlockSizeValue = 64;
            FeedbackSizeValue = 0;
            KeySizeValue = 32;
            ModeValue = CipherMode.ECB;
        }

        public static new Blowfish Create ()
        {
            return new BlowfishImplementation ();
        }
    }
}
