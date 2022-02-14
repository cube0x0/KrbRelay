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
    /// SMB_QUERY_FS_SIZE_INFO
    /// </summary>
    public class QueryFSSizeInfo : QueryFSInformation
    {
        public const int FixedLength = 24;

        public long TotalAllocationUnits;
        public long TotalFreeAllocationUnits;
        public uint SectorsPerAllocationUnit;
        public uint BytesPerSector;

        public QueryFSSizeInfo()
        {
        }

        public QueryFSSizeInfo(byte[] buffer, int offset)
        {
            TotalAllocationUnits = LittleEndianConverter.ToInt64(buffer, 0);
            TotalFreeAllocationUnits = LittleEndianConverter.ToInt64(buffer, 8);
            SectorsPerAllocationUnit = LittleEndianConverter.ToUInt32(buffer, 16);
            BytesPerSector = LittleEndianConverter.ToUInt32(buffer, 20);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            byte[] buffer = new byte[Length];
            LittleEndianWriter.WriteInt64(buffer, 0, TotalAllocationUnits);
            LittleEndianWriter.WriteInt64(buffer, 8, TotalFreeAllocationUnits);
            LittleEndianWriter.WriteUInt32(buffer, 16, SectorsPerAllocationUnit);
            LittleEndianWriter.WriteUInt32(buffer, 20, BytesPerSector);
            return buffer;
        }

        public override int Length
        {
            get
            {
                return FixedLength;
            }
        }

        public override QueryFSInformationLevel InformationLevel
        {
            get
            {
                return QueryFSInformationLevel.SMB_QUERY_FS_SIZE_INFO;
            }
        }
    }
}