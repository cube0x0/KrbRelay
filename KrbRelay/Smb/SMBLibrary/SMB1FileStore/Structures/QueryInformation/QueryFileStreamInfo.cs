/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_QUERY_FILE_STREAM_INFO
    /// </summary>
    public class QueryFileStreamInfo : QueryInformation
    {
        private List<FileStreamEntry> m_entries = new List<FileStreamEntry>();

        public QueryFileStreamInfo()
        {
        }

        public QueryFileStreamInfo(byte[] buffer, int offset)
        {
            if (offset < buffer.Length)
            {
                FileStreamEntry entry;
                do
                {
                    entry = new FileStreamEntry(buffer, offset);
                    m_entries.Add(entry);
                    offset += (int)entry.NextEntryOffset;
                }
                while (entry.NextEntryOffset != 0);
            }
        }

        public override byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            int offset = 0;
            for (int index = 0; index < m_entries.Count; index++)
            {
                FileStreamEntry entry = m_entries[index];
                entry.WriteBytes(buffer, offset);
                int entryLength = entry.Length;
                offset += entryLength;
                if (index < m_entries.Count - 1)
                {
                    // [MS-FSCC] When multiple FILE_STREAM_INFORMATION data elements are present in the buffer, each MUST be aligned on an 8-byte boundary
                    int padding = (8 - (entryLength % 8)) % 8;
                    offset += padding;
                }
            }
            return buffer;
        }

        public List<FileStreamEntry> Entries
        {
            get
            {
                return m_entries;
            }
        }

        public override QueryInformationLevel InformationLevel
        {
            get
            {
                return QueryInformationLevel.SMB_QUERY_FILE_STREAM_INFO;
            }
        }

        public int Length
        {
            get
            {
                int length = 0;
                for (int index = 0; index < m_entries.Count; index++)
                {
                    FileStreamEntry entry = m_entries[index];
                    int entryLength = entry.Length;
                    length += entryLength;
                    if (index < m_entries.Count - 1)
                    {
                        // [MS-FSCC] When multiple FILE_STREAM_INFORMATION data elements are present in the buffer, each MUST be aligned on an 8-byte boundary
                        int padding = (8 - (entryLength % 8)) % 8;
                        length += padding;
                    }
                }
                return length;
            }
        }
    }
}