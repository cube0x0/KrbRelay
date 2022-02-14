/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.15 - FileFullEaInformation
    /// </summary>
    public class FileFullEAInformation : FileInformation
    {
        private List<FileFullEAEntry> m_entries = new List<FileFullEAEntry>();

        public FileFullEAInformation()
        {
        }

        public FileFullEAInformation(byte[] buffer, int offset)
        {
            m_entries = ReadList(buffer, offset);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            WriteList(buffer, offset, m_entries);
        }

        public List<FileFullEAEntry> Entries
        {
            get
            {
                return m_entries;
            }
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileFullEaInformation;
            }
        }

        public override int Length
        {
            get
            {
                int length = 0;
                for (int index = 0; index < m_entries.Count; index++)
                {
                    length += m_entries[index].Length;
                    if (index < m_entries.Count - 1)
                    {
                        // When multiple FILE_FULL_EA_INFORMATION data elements are present in the buffer, each MUST be aligned on a 4-byte boundary
                        int padding = (4 - (length % 4)) % 4;
                        length += padding;
                    }
                }
                return length;
            }
        }

        public static List<FileFullEAEntry> ReadList(byte[] buffer, int offset)
        {
            List<FileFullEAEntry> result = new List<FileFullEAEntry>();
            if (offset < buffer.Length)
            {
                FileFullEAEntry entry;
                do
                {
                    entry = new FileFullEAEntry(buffer, offset);
                    result.Add(entry);
                    offset += (int)entry.NextEntryOffset;
                }
                while (entry.NextEntryOffset != 0);
            }
            return result;
        }

        public static void WriteList(byte[] buffer, int offset, List<FileFullEAEntry> list)
        {
            for (int index = 0; index < list.Count; index++)
            {
                FileFullEAEntry entry = list[index];
                entry.WriteBytes(buffer, offset);
                int entryLength = entry.Length;
                offset += entryLength;
                if (index < list.Count - 1)
                {
                    // When multiple FILE_FULL_EA_INFORMATION data elements are present in the buffer, each MUST be aligned on a 4-byte boundary
                    int padding = (4 - (entryLength % 4)) % 4;
                    offset += padding;
                }
            }
        }
    }
}