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
    /// [MS-FSCC] 2.4.9 - FileCompressionInformation
    /// </summary>
    public class FileCompressionInformation : FileInformation
    {
        public const int FixedLength = 16;

        public long CompressedFileSize;
        public CompressionFormat CompressionFormat;
        public byte CompressionUnitShift;
        public byte ChunkShift;
        public byte ClusterShift;
        public byte[] Reserved; // 3 bytes

        public FileCompressionInformation()
        {
        }

        public FileCompressionInformation(byte[] buffer, int offset)
        {
            CompressedFileSize = LittleEndianConverter.ToInt64(buffer, offset + 0);
            CompressionFormat = (CompressionFormat)LittleEndianConverter.ToUInt16(buffer, offset + 8);
            CompressionUnitShift = ByteReader.ReadByte(buffer, offset + 10);
            ChunkShift = ByteReader.ReadByte(buffer, offset + 11);
            ClusterShift = ByteReader.ReadByte(buffer, offset + 12);
            Reserved = ByteReader.ReadBytes(buffer, offset + 13, 3);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset + 0, CompressedFileSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 8, (ushort)CompressionFormat);
            ByteWriter.WriteByte(buffer, offset + 10, CompressionUnitShift);
            ByteWriter.WriteByte(buffer, offset + 11, ChunkShift);
            ByteWriter.WriteByte(buffer, offset + 12, ClusterShift);
            ByteWriter.WriteBytes(buffer, offset + 13, Reserved, 3);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileCompressionInformation;
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