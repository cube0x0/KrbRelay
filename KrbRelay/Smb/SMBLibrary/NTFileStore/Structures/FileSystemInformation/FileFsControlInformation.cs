/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.5.2 - FileFsControlInformation
    /// </summary>
    public class FileFsControlInformation : FileSystemInformation
    {
        public const int FixedLength = 48;

        public long FreeSpaceStartFiltering;
        public long FreeSpaceThreshold;
        public long FreeSpaceStopFiltering;
        public ulong DefaultQuotaThreshold;
        public ulong DefaultQuotaLimit;
        public FileSystemControlFlags FileSystemControlFlags;
        public uint Padding;

        public FileFsControlInformation()
        {
        }

        public FileFsControlInformation(byte[] buffer, int offset)
        {
            FreeSpaceStartFiltering = LittleEndianConverter.ToInt64(buffer, offset + 0);
            FreeSpaceThreshold = LittleEndianConverter.ToInt64(buffer, offset + 8);
            FreeSpaceStopFiltering = LittleEndianConverter.ToInt64(buffer, offset + 16);
            DefaultQuotaThreshold = LittleEndianConverter.ToUInt64(buffer, offset + 24);
            DefaultQuotaLimit = LittleEndianConverter.ToUInt64(buffer, offset + 32);
            FileSystemControlFlags = (FileSystemControlFlags)LittleEndianConverter.ToUInt32(buffer, offset + 40);
            Padding = LittleEndianConverter.ToUInt32(buffer, offset + 44);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset + 0, FreeSpaceStartFiltering);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, FreeSpaceThreshold);
            LittleEndianWriter.WriteInt64(buffer, offset + 16, FreeSpaceStopFiltering);
            LittleEndianWriter.WriteUInt64(buffer, offset + 24, DefaultQuotaThreshold);
            LittleEndianWriter.WriteUInt64(buffer, offset + 32, DefaultQuotaLimit);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, (uint)FileSystemControlFlags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, Padding);
        }

        public override FileSystemInformationClass FileSystemInformationClass
        {
            get
            {
                return FileSystemInformationClass.FileFsControlInformation;
            }
        }

        public override int Length
        {
            get
            {
                return FixedLength;
            }
        }
    }
}