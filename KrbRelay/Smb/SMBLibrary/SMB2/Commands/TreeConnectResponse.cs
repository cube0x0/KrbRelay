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
    /// SMB2 TREE_CONNECT Response
    /// </summary>
    public class TreeConnectResponse : SMB2Command
    {
        public const int DeclaredSize = 16;

        private ushort StructureSize;
        public ShareType ShareType;
        public byte Reserved;
        public ShareFlags ShareFlags;
        public ShareCapabilities Capabilities;
        public AccessMask MaximalAccess;

        public TreeConnectResponse() : base(SMB2CommandName.TreeConnect)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public TreeConnectResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            ShareType = (ShareType)ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            ShareFlags = (ShareFlags)LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            Capabilities = (ShareCapabilities)LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 8);
            MaximalAccess = (AccessMask)LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 12);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte)ShareType);
            ByteWriter.WriteByte(buffer, offset + 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint)ShareFlags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, (uint)Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, (uint)MaximalAccess);
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