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
    /// SMB2 CLOSE Request
    /// </summary>
    public class CloseRequest : SMB2Command
    {
        public const int DeclaredSize = 24;

        private ushort StructureSize;
        public CloseFlags Flags;
        public uint Reserved;
        public FileID FileId;

        public CloseRequest() : base(SMB2CommandName.Close)
        {
            StructureSize = DeclaredSize;
        }

        public CloseRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Flags = (CloseFlags)LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 8);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, Reserved);
            FileId.WriteBytes(buffer, offset + 8);
        }

        public bool PostQueryAttributes
        {
            get
            {
                return ((this.Flags & CloseFlags.PostQueryAttributes) > 0);
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