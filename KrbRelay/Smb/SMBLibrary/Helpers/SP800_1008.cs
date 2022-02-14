// Adapted from https://referencesource.microsoft.com/#system.web/Security/Cryptography/SP800_108.cs
using System;
using System.Security.Cryptography;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// Implements the NIST SP800-108 key derivation routine in counter mode with an HMAC PRF.
    /// See: http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf
    /// </summary>
    internal class SP800_1008
    {
        public static byte[] DeriveKey(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
        {
            int labelLength = (label != null) ? label.Length : 0;
            int contextLength = (context != null) ? context.Length : 0;
            byte[] buffer = new byte[4 /* [i]_2 */ + labelLength /* label */ + 1 /* 0x00 */ + contextLength /* context */ + 4 /* [L]_2 */];

            if (labelLength != 0)
            {
                Buffer.BlockCopy(label, 0, buffer, 4, labelLength); // the 4 accounts for the [i]_2 length
            }
            if (contextLength != 0)
            {
                Buffer.BlockCopy(context, 0, buffer, 5 + labelLength, contextLength); // the '5 +' accounts for the [i]_2 length, the label, and the 0x00 byte
            }

            BigEndianWriter.WriteUInt32(buffer, 5 + labelLength + contextLength, (uint)keyLengthInBits); // the '5 +' accounts for the [i]_2 length, the label, the 0x00 byte, and the context

            // Initialization
            int numBytesWritten = 0;
            int numBytesRemaining = keyLengthInBits / 8;
            byte[] output = new byte[numBytesRemaining];

            // Calculate each K_i value and copy the leftmost bits to the output buffer as appropriate.
            for (uint i = 1; numBytesRemaining > 0; i++)
            {
                BigEndianWriter.WriteUInt32(buffer, 0, i); // set the first 32 bits of the buffer to be the current iteration value
                byte[] K_i = hmac.ComputeHash(buffer);

                // copy the leftmost bits of K_i into the output buffer
                int numBytesToCopy = Math.Min(numBytesRemaining, K_i.Length);
                Buffer.BlockCopy(K_i, 0, output, numBytesWritten, numBytesToCopy);
                numBytesWritten += numBytesToCopy;
                numBytesRemaining -= numBytesToCopy;
            }

            // finished
            return output;
        }
    }
}