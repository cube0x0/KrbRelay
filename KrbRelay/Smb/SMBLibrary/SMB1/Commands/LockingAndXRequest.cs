/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// LOCKING_ANDX_RANGE32 (10-byte)
    /// or
    /// LOCKING_ANDX_RANGE64 (24-byte )
    /// </summary>
    public class LockingRange
    {
        public const int Length32 = 10;
        public const int Length64 = 20;

        public ushort PID;
        public ulong ByteOffset;
        public ulong LengthInBytes;

        public void Write32(byte[] buffer, ref int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, this.PID);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)this.ByteOffset);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)this.LengthInBytes);
        }

        public void Write64(byte[] buffer, ref int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, this.PID);
            offset += 2; // padding
            LittleEndianWriter.WriteUInt64(buffer, ref offset, this.ByteOffset);
            LittleEndianWriter.WriteUInt64(buffer, ref offset, this.LengthInBytes);
        }

        public static LockingRange Read32(byte[] buffer, ref int offset)
        {
            LockingRange entry = new LockingRange();
            entry.PID = LittleEndianReader.ReadUInt16(buffer, ref offset);
            entry.ByteOffset = LittleEndianReader.ReadUInt32(buffer, ref offset);
            entry.LengthInBytes = LittleEndianReader.ReadUInt32(buffer, ref offset);
            return entry;
        }

        public static LockingRange Read64(byte[] buffer, ref int offset)
        {
            LockingRange entry = new LockingRange();
            entry.PID = LittleEndianReader.ReadUInt16(buffer, ref offset);
            offset += 2; // padding
            entry.ByteOffset = LittleEndianReader.ReadUInt64(buffer, ref offset);
            entry.LengthInBytes = LittleEndianReader.ReadUInt64(buffer, ref offset);
            return entry;
        }
    }

    /// <summary>
    /// SMB_COM_LOCKING_ANDX Request
    /// </summary>
    public class LockingAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 12;

        // Parameters:
        public ushort FID;

        public LockType TypeOfLock;
        public byte NewOpLockLevel;
        public uint Timeout;

        //ushort NumberOfRequestedUnlocks;
        //ushort NumberOfRequestedLocks;
        // Data:
        public List<LockingRange> Unlocks = new List<LockingRange>();

        public List<LockingRange> Locks = new List<LockingRange>();

        public LockingAndXRequest() : base()
        {
        }

        public LockingAndXRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            FID = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            TypeOfLock = (LockType)ByteReader.ReadByte(this.SMBParameters, 6);
            NewOpLockLevel = ByteReader.ReadByte(this.SMBParameters, 7);
            Timeout = LittleEndianConverter.ToUInt32(this.SMBParameters, 8);
            ushort numberOfRequestedUnlocks = LittleEndianConverter.ToUInt16(this.SMBParameters, 12);
            ushort numberOfRequestedLocks = LittleEndianConverter.ToUInt16(this.SMBParameters, 14);

            int dataOffset = 0;
            if ((TypeOfLock & LockType.LARGE_FILES) > 0)
            {
                for (int index = 0; index < numberOfRequestedUnlocks; index++)
                {
                    LockingRange entry = LockingRange.Read64(this.SMBData, ref dataOffset);
                    Unlocks.Add(entry);
                }

                for (int index = 0; index < numberOfRequestedLocks; index++)
                {
                    LockingRange entry = LockingRange.Read64(this.SMBData, ref dataOffset);
                    Locks.Add(entry);
                }
            }
            else
            {
                for (int index = 0; index < numberOfRequestedUnlocks; index++)
                {
                    LockingRange entry = LockingRange.Read32(this.SMBData, ref dataOffset);
                    Unlocks.Add(entry);
                }

                for (int index = 0; index < numberOfRequestedLocks; index++)
                {
                    LockingRange entry = LockingRange.Read32(this.SMBData, ref dataOffset);
                    Locks.Add(entry);
                }
            }
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, FID);
            ByteWriter.WriteByte(this.SMBParameters, 6, (byte)TypeOfLock);
            ByteWriter.WriteByte(this.SMBParameters, 7, NewOpLockLevel);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 8, Timeout);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 12, (ushort)Unlocks.Count);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 14, (ushort)Locks.Count);

            int dataLength;
            bool isLargeFile = (TypeOfLock & LockType.LARGE_FILES) > 0;
            if (isLargeFile)
            {
                dataLength = (Unlocks.Count + Locks.Count) * LockingRange.Length64;
            }
            else
            {
                dataLength = (Unlocks.Count + Locks.Count) * LockingRange.Length32;
            }
            int dataOffset = 0;
            this.SMBData = new byte[dataLength];
            for (int index = 0; index < Unlocks.Count; index++)
            {
                if (isLargeFile)
                {
                    Unlocks[index].Write64(this.SMBData, ref dataOffset);
                }
                else
                {
                    Unlocks[index].Write32(this.SMBData, ref dataOffset);
                }
            }

            for (int index = 0; index < Locks.Count; index++)
            {
                if (isLargeFile)
                {
                    Locks[index].Write64(this.SMBData, ref dataOffset);
                }
                else
                {
                    Locks[index].Write32(this.SMBData, ref dataOffset);
                }
            }
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_LOCKING_ANDX;
            }
        }
    }
}