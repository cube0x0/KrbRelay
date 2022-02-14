/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.41 - FileValidDataLengthInformation
    /// </summary>
    public class FileValidDataLengthInformation : FileInformation
    {
        public const int FixedLength = 8;

        public long ValidDataLength;

        public FileValidDataLengthInformation()
        {
        }

        public FileValidDataLengthInformation(byte[] buffer, int offset)
        {
            ValidDataLength = LittleEndianConverter.ToInt64(buffer, offset);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset, ValidDataLength);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileValidDataLengthInformation;
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