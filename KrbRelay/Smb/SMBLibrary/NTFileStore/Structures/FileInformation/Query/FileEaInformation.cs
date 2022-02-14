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
    /// [MS-FSCC] 2.4.12 - FileEaInformation
    /// </summary>
    public class FileEaInformation : FileInformation
    {
        public const int FixedLength = 4;

        public uint EaSize;

        public FileEaInformation()
        {
        }

        public FileEaInformation(byte[] buffer, int offset)
        {
            EaSize = LittleEndianConverter.ToUInt32(buffer, offset + 0);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, EaSize);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileEaInformation;
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