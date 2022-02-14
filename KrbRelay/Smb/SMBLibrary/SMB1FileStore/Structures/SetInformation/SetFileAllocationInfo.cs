/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_SET_FILE_ALLOCATION_INFO
    /// </summary>
    public class SetFileAllocationInfo : SetInformation
    {
        public const int Length = 8;

        public long AllocationSize;

        public SetFileAllocationInfo()
        {
        }

        public SetFileAllocationInfo(byte[] buffer) : this(buffer, 0)
        {
        }

        public SetFileAllocationInfo(byte[] buffer, int offset)
        {
            AllocationSize = LittleEndianConverter.ToInt64(buffer, offset);
        }

        public override byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            LittleEndianWriter.WriteInt64(buffer, 0, AllocationSize);
            return buffer;
        }

        public override SetInformationLevel InformationLevel
        {
            get
            {
                return SetInformationLevel.SMB_SET_FILE_ALLOCATION_INFO;
            }
        }
    }
}