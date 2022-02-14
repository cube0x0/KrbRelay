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
    /// SMB_SET_FILE_DISPOSITION_INFO
    /// </summary>
    public class SetFileDispositionInfo : SetInformation
    {
        public const int Length = 1;

        /// <summary>
        /// Indicate that a file SHOULD be deleted when it is closed.
        /// </summary>
        public bool DeletePending;

        public SetFileDispositionInfo()
        {
        }

        public SetFileDispositionInfo(byte[] buffer) : this(buffer, 0)
        {
        }

        public SetFileDispositionInfo(byte[] buffer, int offset)
        {
            DeletePending = (ByteReader.ReadByte(buffer, ref offset) > 0);
        }

        public override byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            ByteWriter.WriteByte(buffer, 0, Convert.ToByte(DeletePending));
            return buffer;
        }

        public override SetInformationLevel InformationLevel
        {
            get
            {
                return SetInformationLevel.SMB_SET_FILE_DISPOSITION_INFO;
            }
        }
    }
}