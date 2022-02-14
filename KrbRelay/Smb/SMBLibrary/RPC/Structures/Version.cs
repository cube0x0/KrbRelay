/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// version_t
    /// </summary>
    public struct Version
    {
        public const int Length = 2;

        public byte Major; // major
        public byte Minor; // minor

        public Version(byte[] buffer, int offset)
        {
            Major = ByteReader.ReadByte(buffer, offset + 0);
            Minor = ByteReader.ReadByte(buffer, offset + 1);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteByte(buffer, offset + 0, Major);
            ByteWriter.WriteByte(buffer, offset + 1, Minor);
        }
    }
}