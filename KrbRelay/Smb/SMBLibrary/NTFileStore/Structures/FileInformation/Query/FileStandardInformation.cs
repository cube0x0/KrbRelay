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
    /// [MS-FSCC] 2.4.38 - FileStandardInformation
    /// </summary>
    public class FileStandardInformation : FileInformation
    {
        public const int FixedLength = 24;

        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public bool DeletePending;
        public bool Directory;
        public ushort Reserved;

        public FileStandardInformation()
        {
        }

        public FileStandardInformation(byte[] buffer, int offset)
        {
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset + 0);
            EndOfFile = LittleEndianConverter.ToInt64(buffer, offset + 8);
            NumberOfLinks = LittleEndianConverter.ToUInt32(buffer, offset + 16);
            DeletePending = (ByteReader.ReadByte(buffer, offset + 20) > 0);
            Directory = (ByteReader.ReadByte(buffer, offset + 21) > 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + 22);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset + 0, AllocationSize);
            LittleEndianWriter.WriteInt64(buffer, offset + 8, EndOfFile);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, NumberOfLinks);
            ByteWriter.WriteByte(buffer, offset + 20, Convert.ToByte(DeletePending));
            ByteWriter.WriteByte(buffer, offset + 21, Convert.ToByte(Directory));
            LittleEndianWriter.WriteUInt16(buffer, offset + 22, Reserved);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileStandardInformation;
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