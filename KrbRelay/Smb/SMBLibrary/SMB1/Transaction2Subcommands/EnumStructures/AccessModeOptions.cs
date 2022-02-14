/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public enum AccessMode : byte
    {
        Read = 0x00,
        Write = 0x01,
        ReadWrite = 0x02,
        Execute = 0x03,
    }

    public enum SharingMode : byte
    {
        Compatibility = 0x00,
        DenyReadWriteExecute = 0x01, // Exclusive use
        DenyWrite = 0x02,
        DenyReadExecute = 0x03,
        DenyNothing = 0x04,
    }

    public enum ReferenceLocality : byte
    {
        Unknown = 0x00,
        Sequential = 0x01,
        Random = 0x02,
        RandomWithLocality = 0x03,
    }

    public enum CachedMode : byte
    {
        CachingAllowed = 0x00,
        DoNotCacheFile = 0x01,
    }

    public enum WriteThroughMode : byte
    {
        Disabled = 0x00,

        /// <summary>
        /// Write-through mode.
        /// If this flag is set, then no read ahead or write behind is allowed on this file or device.
        /// When the response is returned, data is expected to be on the disk or device.
        /// </summary>
        WriteThrough = 0x01,
    }

    public struct AccessModeOptions // 2 bytes
    {
        public const int Length = 2;

        public AccessMode AccessMode;
        public SharingMode SharingMode;
        public ReferenceLocality ReferenceLocality;
        public CachedMode CachedMode;
        public WriteThroughMode WriteThroughMode;

        public AccessModeOptions(byte[] buffer, int offset)
        {
            AccessMode = (AccessMode)(buffer[offset + 0] & 0x07);
            SharingMode = (SharingMode)((buffer[offset + 0] & 0x70) >> 4);
            ReferenceLocality = (ReferenceLocality)(buffer[offset + 1] & 0x07);
            CachedMode = (CachedMode)((buffer[offset + 1] & 0x10) >> 4);
            WriteThroughMode = (WriteThroughMode)((buffer[offset + 1] & 0x40) >> 6);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)((byte)AccessMode & 0x07);
            buffer[offset + 0] |= (byte)(((byte)SharingMode << 4) & 0x70);
            buffer[offset + 1] = (byte)((byte)ReferenceLocality & 0x07);
            buffer[offset + 1] |= (byte)(((byte)CachedMode << 4) & 0x10);
            buffer[offset + 1] |= (byte)(((byte)WriteThroughMode << 6) & 0x40);
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            WriteBytes(buffer, offset);
            offset += Length;
        }

        public static AccessModeOptions Read(byte[] buffer, ref int offset)
        {
            offset += Length;
            return new AccessModeOptions(buffer, offset - Length);
        }
    }
}