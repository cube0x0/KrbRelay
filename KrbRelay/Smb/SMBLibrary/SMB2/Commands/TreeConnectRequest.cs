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
    /// SMB2 TREE_CONNECT Request
    /// </summary>
    public class TreeConnectRequest : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        public ushort Reserved;
        private ushort PathOffset;
        private ushort PathLength;
        public string Path = String.Empty;

        public TreeConnectRequest() : base(SMB2CommandName.TreeConnect)
        {
            StructureSize = DeclaredSize;
        }

        public TreeConnectRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            PathOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 4);
            PathLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 6);
            if (PathLength > 0)
            {
                Path = ByteReader.ReadUTF16String(buffer, offset + PathOffset, PathLength / 2);
            }
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            PathOffset = 0;
            PathLength = (ushort)(Path.Length * 2);
            if (Path.Length > 0)
            {
                PathOffset = SMB2Header.Length + 8;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, PathOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, PathLength);
            if (Path.Length > 0)
            {
                ByteWriter.WriteUTF16String(buffer, offset + 8, Path);
            }
        }

        public override int CommandLength
        {
            get
            {
                return 8 + Path.Length * 2;
            }
        }
    }
}