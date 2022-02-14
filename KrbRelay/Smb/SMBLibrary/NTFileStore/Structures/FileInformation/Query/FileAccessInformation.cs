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
    /// [MS-FSCC] 2.4.1 - FileAccessInformation
    /// </summary>
    public class FileAccessInformation : FileInformation
    {
        public const int FixedLength = 4;

        public AccessMask AccessFlags;

        public FileAccessInformation()
        {
        }

        public FileAccessInformation(byte[] buffer, int offset)
        {
            AccessFlags = (AccessMask)LittleEndianConverter.ToUInt32(buffer, offset + 0);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, (uint)AccessFlags);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileAccessInformation;
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