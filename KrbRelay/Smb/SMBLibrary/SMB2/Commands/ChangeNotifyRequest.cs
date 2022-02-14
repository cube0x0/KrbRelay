/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 CHANGE_NOTIFY Request
    /// </summary>
    public class ChangeNotifyRequest : SMB2Command
    {
        public const int DeclaredSize = 32;

        private ushort StructureSize;
        public ChangeNotifyFlags Flags;
        public uint OutputBufferLength;
        public FileID FileId;
        public NotifyChangeFilter CompletionFilter;
        public uint Reserved;

        public ChangeNotifyRequest() : base(SMB2CommandName.ChangeNotify)
        {
            StructureSize = DeclaredSize;
        }

        public ChangeNotifyRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Flags = (ChangeNotifyFlags)LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 8);
            CompletionFilter = (NotifyChangeFilter)LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 24);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 28);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, OutputBufferLength);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, (uint)CompletionFilter);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, Reserved);
        }

        public bool WatchTree
        {
            get
            {
                return ((Flags & ChangeNotifyFlags.WatchTree) > 0);
            }
            set
            {
                if (value)
                {
                    Flags |= ChangeNotifyFlags.WatchTree;
                }
                else
                {
                    Flags &= ~ChangeNotifyFlags.WatchTree;
                }
            }
        }

        public override int CommandLength
        {
            get
            {
                return DeclaredSize;
            }
        }
    }
}