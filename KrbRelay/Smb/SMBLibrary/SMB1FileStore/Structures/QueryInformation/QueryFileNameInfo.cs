/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_QUERY_FILE_NAME_INFO
    /// </summary>
    public class QueryFileNameInfo : QueryInformation
    {
        //uint FileNameLength; // In bytes
        public string FileName; // Unicode

        public QueryFileNameInfo()
        {
        }

        public QueryFileNameInfo(byte[] buffer, int offset)
        {
            uint fileNameLength = LittleEndianConverter.ToUInt32(buffer, 0);
            FileName = ByteReader.ReadUTF16String(buffer, 4, (int)(fileNameLength / 2));
        }

        public override byte[] GetBytes()
        {
            uint fileNameLength = (uint)(FileName.Length * 2);
            byte[] buffer = new byte[4 + fileNameLength];
            LittleEndianWriter.WriteUInt32(buffer, 0, fileNameLength);
            ByteWriter.WriteUTF16String(buffer, 4, FileName);
            return buffer;
        }

        public override QueryInformationLevel InformationLevel
        {
            get
            {
                return QueryInformationLevel.SMB_QUERY_FILE_NAME_INFO;
            }
        }
    }
}