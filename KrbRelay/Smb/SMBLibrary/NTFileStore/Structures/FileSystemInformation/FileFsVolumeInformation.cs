/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.5.9 - FileFsVolumeInformation
    /// </summary>
    public class FileFsVolumeInformation : FileSystemInformation
    {
        public const int FixedLength = 18;

        public DateTime? VolumeCreationTime;
        public uint VolumeSerialNumber;
        private uint VolumeLabelLength;
        public bool SupportsObjects;
        public byte Reserved;
        public string VolumeLabel = String.Empty;

        public FileFsVolumeInformation()
        {
        }

        public FileFsVolumeInformation(byte[] buffer, int offset)
        {
            VolumeCreationTime = FileTimeHelper.ReadNullableFileTime(buffer, offset + 0);
            VolumeSerialNumber = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            VolumeLabelLength = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            SupportsObjects = Convert.ToBoolean(ByteReader.ReadByte(buffer, offset + 16));
            Reserved = ByteReader.ReadByte(buffer, offset + 17);
            if (VolumeLabelLength > 0)
            {
                VolumeLabel = ByteReader.ReadUTF16String(buffer, offset + 18, (int)VolumeLabelLength / 2);
            }
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            VolumeLabelLength = (uint)(VolumeLabel.Length * 2);
            FileTimeHelper.WriteFileTime(buffer, offset + 0, VolumeCreationTime);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, VolumeSerialNumber);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, VolumeLabelLength);
            ByteWriter.WriteByte(buffer, offset + 16, Convert.ToByte(SupportsObjects));
            ByteWriter.WriteByte(buffer, offset + 17, Reserved);
            ByteWriter.WriteUTF16String(buffer, offset + 18, VolumeLabel);
        }

        public override FileSystemInformationClass FileSystemInformationClass
        {
            get
            {
                return FileSystemInformationClass.FileFsVolumeInformation;
            }
        }

        public override int Length
        {
            get
            {
                return FixedLength + VolumeLabel.Length * 2;
            }
        }
    }
}