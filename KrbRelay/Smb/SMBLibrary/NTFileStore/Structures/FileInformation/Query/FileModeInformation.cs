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
    /// [MS-FSCC] 2.4.24 - FileModeInformation
    /// </summary>
    public class FileModeInformation : FileInformation
    {
        public const int FixedSize = 4;

        public CreateOptions FileMode;

        public FileModeInformation()
        {
        }

        public FileModeInformation(byte[] buffer, int offset)
        {
            FileMode = (CreateOptions)LittleEndianConverter.ToUInt32(buffer, offset + 0);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset, (uint)FileMode);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileModeInformation;
            }
        }

        public override int Length
        {
            get
            {
                return FixedSize;
            }
        }
    }
}