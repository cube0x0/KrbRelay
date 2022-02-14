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
    /// [MS-FSCC] 2.4.26 - FileNamesInformation
    /// </summary>
    public class FileNamesInformation : QueryDirectoryFileInformation
    {
        public const int FixedLength = 12;

        private uint FileNameLength;
        public string FileName = String.Empty;

        public FileNamesInformation()
        {
        }

        public FileNamesInformation(byte[] buffer, int offset) : base(buffer, offset)
        {
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileName = ByteReader.ReadUTF16String(buffer, offset + 12, (int)FileNameLength / 2);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            base.WriteBytes(buffer, offset);
            FileNameLength = (uint)(FileName.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, FileNameLength);
            ByteWriter.WriteUTF16String(buffer, offset + 12, FileName);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileNamesInformation;
            }
        }

        public override int Length
        {
            get
            {
                return FixedLength + FileName.Length * 2;
            }
        }
    }
}