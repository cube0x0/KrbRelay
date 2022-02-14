/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 QUERY_DIRECTORY Request
    /// </summary>
    public class QueryDirectoryRequest : SMB2Command
    {
        public const int FixedLength = 32;
        public const int DeclaredSize = 33;

        private ushort StructureSize;
        public FileInformationClass FileInformationClass;
        public QueryDirectoryFlags Flags;
        public uint FileIndex;
        public FileID FileId;
        private ushort FileNameOffset;
        private ushort FileNameLength;
        public uint OutputBufferLength;
        public string FileName = String.Empty;

        public QueryDirectoryRequest() : base(SMB2CommandName.QueryDirectory)
        {
            StructureSize = DeclaredSize;
        }

        public QueryDirectoryRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            FileInformationClass = (FileInformationClass)ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            Flags = (QueryDirectoryFlags)ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            FileIndex = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 8);
            FileNameOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 24);
            FileNameLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 26);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 28);
            FileName = ByteReader.ReadUTF16String(buffer, offset + FileNameOffset, FileNameLength / 2);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            FileNameOffset = 0;
            FileNameLength = (ushort)(FileName.Length * 2);
            if (FileName.Length > 0)
            {
                FileNameOffset = SMB2Header.Length + FixedLength;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte)FileInformationClass);
            ByteWriter.WriteByte(buffer, offset + 3, (byte)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, FileIndex);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt16(buffer, offset + 24, FileNameOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 26, FileNameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, OutputBufferLength);
            ByteWriter.WriteUTF16String(buffer, offset + 32, FileName);
        }

        public bool Restart
        {
            get
            {
                return ((this.Flags & QueryDirectoryFlags.SMB2_RESTART_SCANS) > 0);
            }
            set
            {
                if (value)
                {
                    Flags |= QueryDirectoryFlags.SMB2_RESTART_SCANS;
                }
                else
                {
                    Flags &= ~QueryDirectoryFlags.SMB2_RESTART_SCANS;
                }
            }
        }

        public bool ReturnSingleEntry
        {
            get
            {
                return ((this.Flags & QueryDirectoryFlags.SMB2_RETURN_SINGLE_ENTRY) > 0);
            }
            set
            {
                if (value)
                {
                    Flags |= QueryDirectoryFlags.SMB2_RETURN_SINGLE_ENTRY;
                }
                else
                {
                    Flags &= ~QueryDirectoryFlags.SMB2_RETURN_SINGLE_ENTRY;
                }
            }
        }

        public bool Reopen
        {
            get
            {
                return ((this.Flags & QueryDirectoryFlags.SMB2_REOPEN) > 0);
            }
            set
            {
                if (value)
                {
                    Flags |= QueryDirectoryFlags.SMB2_REOPEN;
                }
                else
                {
                    Flags &= ~QueryDirectoryFlags.SMB2_REOPEN;
                }
            }
        }

        public override int CommandLength
        {
            get
            {
                return FixedLength + FileName.Length * 2;
            }
        }
    }
}