/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 LOCK Request
    /// </summary>
    public class LockRequest : SMB2Command
    {
        public const int DeclaredSize = 48;

        private ushort StructureSize;

        // ushort LockCount;
        public byte LSN; // 4 bits

        public uint LockSequenceIndex; // 28 bits
        public FileID FileId;
        public List<LockElement> Locks;

        public LockRequest() : base(SMB2CommandName.Lock)
        {
            StructureSize = DeclaredSize;
        }

        public LockRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            ushort lockCount = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            uint temp = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            LSN = (byte)(temp >> 28);
            LockSequenceIndex = (temp & 0x0FFFFFFF);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 8);
            Locks = LockElement.ReadLockList(buffer, offset + SMB2Header.Length + 24, (int)lockCount);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort)Locks.Count);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint)(LSN & 0x0F) << 28 | (uint)(LockSequenceIndex & 0x0FFFFFFF));
            FileId.WriteBytes(buffer, offset + 8);
            LockElement.WriteLockList(buffer, offset + 24, Locks);
        }

        public override int CommandLength
        {
            get
            {
                return 48 + Locks.Count * LockElement.StructureLength;
            }
        }
    }
}