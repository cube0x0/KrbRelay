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
    /// SMB_FIND_FILE_DIRECTORY_INFO
    /// </summary>
    public class FindFileDirectoryInfo : FindInformation
    {
        public const int FixedLength = 64;

        // uint NextEntryOffset;
        public uint FileIndex; // SHOULD be set to zero when sent in a response and SHOULD be ignored when received by the client

        public DateTime? CreationTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? LastAttrChangeTime;
        public long EndOfFile;
        public long AllocationSize;
        public ExtendedFileAttributes ExtFileAttributes;

        //uint FileNameLength; // In bytes, MUST exclude the null termination.
        public string FileName; // OEM / Unicode character array. MUST be written as SMB_STRING, and read as fixed length string.

        public FindFileDirectoryInfo() : base()
        {
        }

        public FindFileDirectoryInfo(byte[] buffer, int offset, bool isUnicode) : base()
        {
            NextEntryOffset = LittleEndianReader.ReadUInt32(buffer, ref offset);
            FileIndex = LittleEndianReader.ReadUInt32(buffer, ref offset);
            CreationTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            LastAttrChangeTime = FileTimeHelper.ReadNullableFileTime(buffer, ref offset);
            EndOfFile = LittleEndianReader.ReadInt64(buffer, ref offset);
            AllocationSize = LittleEndianReader.ReadInt64(buffer, ref offset);
            ExtFileAttributes = (ExtendedFileAttributes)LittleEndianReader.ReadUInt32(buffer, ref offset);
            uint fileNameLength = LittleEndianReader.ReadUInt32(buffer, ref offset);
            FileName = SMB1Helper.ReadFixedLengthString(buffer, ref offset, isUnicode, (int)fileNameLength);
        }

        public override void WriteBytes(byte[] buffer, ref int offset, bool isUnicode)
        {
            uint fileNameLength = (byte)(isUnicode ? FileName.Length * 2 : FileName.Length);

            LittleEndianWriter.WriteUInt32(buffer, ref offset, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, FileIndex);
            FileTimeHelper.WriteFileTime(buffer, ref offset, CreationTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastAccessTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastWriteTime);
            FileTimeHelper.WriteFileTime(buffer, ref offset, LastAttrChangeTime);
            LittleEndianWriter.WriteInt64(buffer, ref offset, EndOfFile);
            LittleEndianWriter.WriteInt64(buffer, ref offset, AllocationSize);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, fileNameLength);
            SMB1Helper.WriteSMBString(buffer, ref offset, isUnicode, FileName);
        }

        public override int GetLength(bool isUnicode)
        {
            int length = FixedLength;

            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }
            return length;
        }

        public override FindInformationLevel InformationLevel
        {
            get
            {
                return FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO;
            }
        }
    }
}