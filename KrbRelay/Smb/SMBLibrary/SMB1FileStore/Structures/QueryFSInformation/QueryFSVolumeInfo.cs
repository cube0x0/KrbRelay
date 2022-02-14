/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_QUERY_FS_VOLUME_INFO
    /// </summary>
    public class QueryFSVolumeInfo : QueryFSInformation
    {
        public const int FixedLength = 18;

        public DateTime? VolumeCreationTime;
        public uint SerialNumber;
        private uint VolumeLabelSize;
        public ushort Reserved;
        public string VolumeLabel; // Unicode

        public QueryFSVolumeInfo()
        {
            VolumeLabel = String.Empty;
        }

        public QueryFSVolumeInfo(byte[] buffer, int offset)
        {
            VolumeCreationTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + 0);
            SerialNumber = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            VolumeLabelSize = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + 16);
            VolumeLabel = ByteReader.ReadUTF16String(buffer, offset + 18, (int)VolumeLabelSize);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            VolumeLabelSize = (uint)(VolumeLabel.Length * 2);

            byte[] buffer = new byte[this.Length];
            FileTimeHelper.WriteFileTime(buffer, 0, VolumeCreationTime);
            LittleEndianWriter.WriteUInt32(buffer, 8, SerialNumber);
            LittleEndianWriter.WriteUInt32(buffer, 12, VolumeLabelSize);
            LittleEndianWriter.WriteUInt16(buffer, 16, Reserved);
            ByteWriter.WriteUTF16String(buffer, 18, VolumeLabel);
            return buffer;
        }

        public override int Length
        {
            get
            {
                return FixedLength + VolumeLabel.Length * 2;
            }
        }

        public override QueryFSInformationLevel InformationLevel
        {
            get
            {
                return QueryFSInformationLevel.SMB_QUERY_FS_VOLUME_INFO;
            }
        }
    }
}