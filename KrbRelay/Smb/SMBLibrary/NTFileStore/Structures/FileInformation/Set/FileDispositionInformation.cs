/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// [MS-FSCC] 2.4.11 - FileDispositionInformation
    /// </summary>
    public class FileDispositionInformation : FileInformation
    {
        public const int FixedLength = 1;

        public bool DeletePending;

        public FileDispositionInformation()
        {
        }

        public FileDispositionInformation(byte[] buffer, int offset)
        {
            DeletePending = Convert.ToBoolean(ByteReader.ReadByte(buffer, offset + 0));
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteByte(buffer, offset + 0, Convert.ToByte(DeletePending));
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileDispositionInformation;
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