/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_QUERY_FILE_COMPRESSION_INFO
    /// </summary>
    public class QueryFileCompressionInfo : QueryInformation
    {
        public const int Length = 16;

        public long CompressedFileSize;
        public CompressionFormat CompressionFormat;
        public byte CompressionUnitShift;
        public byte ChunkShift;
        public byte ClusterShift;
        public byte[] Reserved; // 3 bytes

        public QueryFileCompressionInfo()
        {
            Reserved = new byte[3];
        }

        public QueryFileCompressionInfo(byte[] buffer, int offset)
        {
            CompressedFileSize = LittleEndianReader.ReadInt64(buffer, ref offset);
            CompressionFormat = (CompressionFormat)LittleEndianReader.ReadUInt16(buffer, ref offset);
            CompressionUnitShift = ByteReader.ReadByte(buffer, ref offset);
            ChunkShift = ByteReader.ReadByte(buffer, ref offset);
            ClusterShift = ByteReader.ReadByte(buffer, ref offset);
            Reserved = ByteReader.ReadBytes(buffer, ref offset, 3);
        }

        public override byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            int offset = 0;
            LittleEndianWriter.WriteInt64(buffer, ref offset, CompressedFileSize);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)CompressionFormat);
            ByteWriter.WriteByte(buffer, ref offset, CompressionUnitShift);
            ByteWriter.WriteByte(buffer, ref offset, ChunkShift);
            ByteWriter.WriteByte(buffer, ref offset, ClusterShift);
            ByteWriter.WriteBytes(buffer, ref offset, Reserved, 3);
            return buffer;
        }

        public override QueryInformationLevel InformationLevel
        {
            get
            {
                return QueryInformationLevel.SMB_QUERY_FILE_COMPRESSION_INFO;
            }
        }
    }
}