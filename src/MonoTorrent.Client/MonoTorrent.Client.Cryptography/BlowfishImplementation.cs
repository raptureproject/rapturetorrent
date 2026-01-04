using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;

namespace MonoTorrent.Client.Cryptography
{
    internal sealed class BlowfishImplementation : Blowfish
    {
        public sealed override ICryptoTransform CreateEncryptor ()
        {
            return new BlowfishTransform (Key, true);
        }

        public override ICryptoTransform CreateEncryptor (byte[] rgbKey, byte[]? rgbIV)
        {
            return new BlowfishTransform (rgbKey, true);
        }

        public sealed override ICryptoTransform CreateDecryptor ()
        {
            return new BlowfishTransform (Key, false);
        }

        public sealed override ICryptoTransform CreateDecryptor (byte[] rgbKey, byte[]? rgbIV)
        {
            return new BlowfishTransform (rgbKey, false);
        }

        public sealed override void GenerateIV ()
        {
            byte[] ret = new byte[BlockSize / 8];
            RandomNumberGenerator.Fill (ret);
            IV = ret;
        }

        public sealed override void GenerateKey ()
        {
            byte[] ret = new byte[KeySize / 8];
            RandomNumberGenerator.Fill (ret);
            Key = ret;
        }

        public bool TryEncryptEcbCore (ReadOnlySpan<byte> plaintext, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
        {
            using var cipher = new BlowfishTransform (Key, true);
            return ProcessCipher (cipher, plaintext, destination, out bytesWritten);
        }

        public bool TryDecryptEcbCore (ReadOnlySpan<byte> ciphertext, Span<byte> destination, PaddingMode paddingMode, out int bytesWritten)
        {
            using var cipher = new BlowfishTransform (Key, false);
            return ProcessCipher (cipher, ciphertext, destination, out bytesWritten);
        }

        private static bool ProcessCipher (BlowfishTransform cipher, ReadOnlySpan<byte> input, Span<byte> output, out int bytesWritten)
        {
            if (input.Length % 8 != 0) {
                throw new CryptographicException ("Input must be a multiple of 8.");
            }

            for (var i = 0; i < input.Length; i += 8) {
                cipher.TransformBlock (input, i, 8, output, i);
            }

            bytesWritten = input.Length;
            return true;
        }

        protected sealed override void Dispose (bool disposing)
        {
            base.Dispose (disposing);
        }
    }
}
