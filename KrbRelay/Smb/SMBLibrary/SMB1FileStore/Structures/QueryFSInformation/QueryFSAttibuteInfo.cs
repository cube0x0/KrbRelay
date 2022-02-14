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
    /// SMB_QUERY_FS_ATTRIBUTE_INFO
    /// </summary>
    public class QueryFSAttibuteInfo : QueryFSInformation
    {
        public const int FixedLength = 12;

        public FileSystemAttributes FileSystemAttributes;
        public uint MaxFileNameLengthInBytes;

        //uint LengthOfFileSystemName; // In bytes
        public string FileSystemName; // Unicode

        public QueryFSAttibuteInfo()
        {
        }

        public QueryFSAttibuteInfo(byte[] buffer, int offset)
        {
            FileSystemAttributes = (FileSystemAttributes)LittleEndianConverter.ToUInt32(buffer, offset + 0);
            MaxFileNameLengthInBytes = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            uint lengthOfFileSystemName = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileSystemName = ByteReader.ReadUTF16String(buffer, offset + 12, (int)(lengthOfFileSystemName / 2));
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            uint lengthOfFileSystemName = (uint)(FileSystemName.Length * 2);
            byte[] buffer = new byte[this.Length];
            LittleEndianWriter.WriteUInt32(buffer, 0, (uint)FileSystemAttributes);
            LittleEndianWriter.WriteUInt32(buffer, 4, MaxFileNameLengthInBytes);
            LittleEndianWriter.WriteUInt32(buffer, 8, lengthOfFileSystemName);
            ByteWriter.WriteUTF16String(buffer, 12, FileSystemName);
            return buffer;
        }

        public override int Length
        {
            get
            {
                return FixedLength + FileSystemName.Length * 2;
            }
        }

        public override QueryFSInformationLevel InformationLevel
        {
            get
            {
                return QueryFSInformationLevel.SMB_QUERY_FS_ATTRIBUTE_INFO;
            }
        }
    }
}