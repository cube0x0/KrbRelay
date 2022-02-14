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
    /// [MS-FSCC] 2.5.8 - FileFsSizeInformation
    /// </summary>
    public class FileFsSizeInformation : FileSystemInformation
    {
        public const int FixedLength = 24;

        public long TotalAllocationUnits;
        public long AvailableAllocationUnits;
        public uint SectorsPerAllocationUnit;
        public uint BytesPerSector;

        public FileFsSizeInformation()
        {
        }

        public FileFsSizeInformation(byte[] buffer, int offset)
        {
            TotalAllocationUnits = LittleEndianConverter.ToInt64(buffer, offset + 0);
            AvailableAllocationUnits = LittleEndianConverter.ToInt64(buffer, offset + 8);
            SectorsPerAllocationUnit = LittleEndianConverter.ToUInt32(buffer, offset + 16);
            BytesPerSector = LittleEndianConverter.ToUInt32(buffer, offset + 20);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset + 0, TotalAllocationUnits);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, AvailableAllocationUnits);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, SectorsPerAllocationUnit);
            LittleEndianWriter.WriteUInt32(buffer, offset + 20, BytesPerSector);
        }

        public override FileSystemInformationClass FileSystemInformationClass
        {
            get
            {
                return FileSystemInformationClass.FileFsSizeInformation;
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