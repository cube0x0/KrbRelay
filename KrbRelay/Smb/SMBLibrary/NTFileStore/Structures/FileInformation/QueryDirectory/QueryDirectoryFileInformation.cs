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
    public abstract class QueryDirectoryFileInformation : FileInformation
    {
        public uint NextEntryOffset;
        public uint FileIndex;

        public QueryDirectoryFileInformation()
        {
        }

        public QueryDirectoryFileInformation(byte[] buffer, int offset)
        {
            NextEntryOffset = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            FileIndex = LittleEndianConverter.ToUInt32(buffer, offset + 4);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, FileIndex);
        }

        public static QueryDirectoryFileInformation ReadFileInformation(byte[] buffer, int offset, FileInformationClass fileInformationClass)
        {
            switch (fileInformationClass)
            {
                case FileInformationClass.FileDirectoryInformation:
                    return new FileDirectoryInformation(buffer, offset);

                case FileInformationClass.FileFullDirectoryInformation:
                    return new FileFullDirectoryInformation(buffer, offset);

                case FileInformationClass.FileBothDirectoryInformation:
                    return new FileBothDirectoryInformation(buffer, offset);

                case FileInformationClass.FileNamesInformation:
                    return new FileNamesInformation(buffer, offset);

                case FileInformationClass.FileIdBothDirectoryInformation:
                    return new FileIdBothDirectoryInformation(buffer, offset);

                case FileInformationClass.FileIdFullDirectoryInformation:
                    return new FileIdFullDirectoryInformation(buffer, offset);

                default:
                    throw new NotImplementedException(String.Format("File information class {0} is not supported.", (int)fileInformationClass));
            }
        }

        public static List<QueryDirectoryFileInformation> ReadFileInformationList(byte[] buffer, int offset, FileInformationClass fileInformationClass)
        {
            List<QueryDirectoryFileInformation> result = new List<QueryDirectoryFileInformation>();
            QueryDirectoryFileInformation entry;
            do
            {
                entry = ReadFileInformation(buffer, offset, fileInformationClass);
                result.Add(entry);
                offset += (int)entry.NextEntryOffset;
            }
            while (entry.NextEntryOffset != 0);
            return result;
        }

        public static byte[] GetBytes(List<QueryDirectoryFileInformation> fileInformationList)
        {
            int listLength = GetListLength(fileInformationList);
            byte[] buffer = new byte[listLength];
            int offset = 0;
            for (int index = 0; index < fileInformationList.Count; index++)
            {
                QueryDirectoryFileInformation entry = fileInformationList[index];
                int length = entry.Length;
                int paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                if (index < fileInformationList.Count - 1)
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

        public static int GetListLength(List<QueryDirectoryFileInformation> fileInformationList)
        {
            int result = 0;
            for (int index = 0; index < fileInformationList.Count; index++)
            {
                QueryDirectoryFileInformation entry = fileInformationList[index];
                int length = entry.Length;
                // [MS-FSCC] each [entry] MUST be aligned on an 8-byte boundary.
                if (index < fileInformationList.Count - 1)
                {
                    // No padding is required following the last data element.
                    int paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
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