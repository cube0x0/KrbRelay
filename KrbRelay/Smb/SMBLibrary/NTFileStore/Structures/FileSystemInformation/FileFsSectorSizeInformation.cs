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
    /// [MS-FSCC] 2.5.4 - FileFsSectorSizeInformation
    /// </summary>
    public class FileFsSectorSizeInformation : FileSystemInformation
    {
        public const int FixedLength = 28;

        public uint LogicalBytesPerSector;
        public uint PhysicalBytesPerSectorForAtomicity;
        public uint PhysicalBytesPerSectorForPerformance;
        public uint FileSystemEffectivePhysicalBytesPerSectorForAtomicity;
        public SectorSizeInformationFlags Flags;
        public uint ByteOffsetForSectorAlignment;
        public uint ByteOffsetForPartitionAlignment;

        public FileFsSectorSizeInformation()
        {
        }

        public FileFsSectorSizeInformation(byte[] buffer, int offset)
        {
            LogicalBytesPerSector = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            PhysicalBytesPerSectorForAtomicity = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            PhysicalBytesPerSectorForPerformance = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileSystemEffectivePhysicalBytesPerSectorForAtomicity = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            Flags = (SectorSizeInformationFlags)LittleEndianConverter.ToUInt32(buffer, offset + 16);
            ByteOffsetForSectorAlignment = LittleEndianConverter.ToUInt32(buffer, offset + 20);
            ByteOffsetForPartitionAlignment = LittleEndianConverter.ToUInt32(buffer, offset + 24);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, LogicalBytesPerSector);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, PhysicalBytesPerSectorForAtomicity);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, PhysicalBytesPerSectorForPerformance);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, FileSystemEffectivePhysicalBytesPerSectorForAtomicity);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, (uint)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 20, ByteOffsetForSectorAlignment);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, ByteOffsetForPartitionAlignment);
        }

        public override FileSystemInformationClass FileSystemInformationClass
        {
            get
            {
                return FileSystemInformationClass.FileFsSectorSizeInformation;
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