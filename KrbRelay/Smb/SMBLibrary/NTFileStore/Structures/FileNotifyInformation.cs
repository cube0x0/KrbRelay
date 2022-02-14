/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary
{
    public enum FileAction : uint
    {
        Added = 0x00000001,               // FILE_ACTION_ADDED
        Removed = 0x00000002,             // FILE_ACTION_REMOVED
        Modified = 0x00000003,            // FILE_ACTION_MODIFIED
        RenamedOldName = 0x00000004,      // FILE_ACTION_RENAMED_OLD_NAME
        RenamedNewName = 0x00000005,      // FILE_ACTION_RENAMED_NEW_NAME
        AddedStream = 0x00000006,         // FILE_ACTION_ADDED_STREAM
        RemovedStream = 0x00000007,       // FILE_ACTION_REMOVED_STREAM
        ModifiedStream = 0x00000008,      // FILE_ACTION_MODIFIED_STREAM
        RemovedByDelete = 0x00000009,     // FILE_ACTION_REMOVED_BY_DELETE
        IDNotTunneled = 0x0000000A,       // FILE_ACTION_ID_NOT_TUNNELLED
        TunneledIDCollision = 0x0000000B, // FILE_ACTION_TUNNELLED_ID_COLLISION
    }

    /// <summary>
    /// [MS-FSCC] 2.4.42 - FileNotifyInformation
    /// </summary>
    public class FileNotifyInformation
    {
        public const int FixedLength = 12;

        public uint NextEntryOffset;
        public FileAction Action;
        private uint FileNameLength;
        public string FileName;

        public FileNotifyInformation()
        {
            FileName = String.Empty;
        }

        public FileNotifyInformation(byte[] buffer, int offset)
        {
            NextEntryOffset = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            Action = (FileAction)LittleEndianConverter.ToUInt32(buffer, offset + 4);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileName = ByteReader.ReadUTF16String(buffer, offset + 12, (int)(FileNameLength / 2));
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            FileNameLength = (uint)(FileName.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint)Action);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, FileNameLength);
            ByteWriter.WriteUTF16String(buffer, offset + 12, FileName);
        }

        public int Length
        {
            get
            {
                return FixedLength + FileName.Length * 2;
            }
        }

        public static List<FileNotifyInformation> ReadList(byte[] buffer, int offset)
        {
            List<FileNotifyInformation> result = new List<FileNotifyInformation>();
            FileNotifyInformation entry;
            do
            {
                entry = new FileNotifyInformation(buffer, offset);
                result.Add(entry);
                offset += (int)entry.NextEntryOffset;
            }
            while (entry.NextEntryOffset != 0);
            return result;
        }

        public static byte[] GetBytes(List<FileNotifyInformation> notifyInformationList)
        {
            int listLength = GetListLength(notifyInformationList);
            byte[] buffer = new byte[listLength];
            int offset = 0;
            for (int index = 0; index < notifyInformationList.Count; index++)
            {
                FileNotifyInformation entry = notifyInformationList[index];
                int length = entry.Length;
                int paddedLength = (int)Math.Ceiling((double)length / 4) * 4;
                if (index < notifyInformationList.Count - 1)
                {
                    entry.NextEntryOffset = (uint)paddedLength;
                }
                else
                {
                    entry.NextEntryOffset = 0;
                }
                entry.WriteBytes(buffer, offset);
                offset += paddedLength;
            }
            return buffer;
        }

        public static int GetListLength(List<FileNotifyInformation> notifyInformationList)
        {
            int result = 0;
            for (int index = 0; index < notifyInformationList.Count; index++)
            {
                FileNotifyInformation entry = notifyInformationList[index];
                int length = entry.Length;
                // [MS-FSCC] NextEntryOffset MUST always be an integral multiple of 4.
                // The FileName array MUST be padded to the next 4-byte boundary counted from the beginning of the structure.
                if (index < notifyInformationList.Count - 1)
                {
                    // No padding is required following the last data element.
                    int paddedLength = (int)Math.Ceiling((double)length / 4) * 4;
                    result += paddedLength;
                }
                else
                {
                    result += length;
                }
            }
            return result;
        }
    }
}