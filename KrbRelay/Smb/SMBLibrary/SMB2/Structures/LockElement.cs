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
    public struct LockElement
    {
        public const int StructureLength = 24;

        public ulong Offset;
        public ulong Length;
        public LockFlags Flags;
        public uint Reserved;

        public LockElement(byte[] buffer, int offset)
        {
            Offset = LittleEndianConverter.ToUInt64(buffer, offset + 0);
            Length = LittleEndianConverter.ToUInt64(buffer, offset + 8);
            Flags = (LockFlags)LittleEndianConverter.ToUInt32(buffer, offset + 16);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + 20);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt64(buffer, offset + 0, Offset);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, Length);
            LittleEndianWriter.WriteUInt64(buffer, offset + 16, (uint)Flags);
            LittleEndianWriter.WriteUInt64(buffer, offset + 20, Reserved);
        }

        public bool SharedLock
        {
            get
            {
                return (Flags & LockFlags.SharedLock) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= LockFlags.SharedLock;
                }
                else
                {
                    Flags &= ~LockFlags.SharedLock;
                }
            }
        }

        public bool ExclusiveLock
        {
            get
            {
                return (Flags & LockFlags.ExclusiveLock) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= LockFlags.ExclusiveLock;
                }
                else
                {
                    Flags &= ~LockFlags.ExclusiveLock;
                }
            }
        }

        public bool Unlock
        {
            get
            {
                return (Flags & LockFlags.Unlock) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= LockFlags.Unlock;
                }
                else
                {
                    Flags &= ~LockFlags.Unlock;
                }
            }
        }

        public bool FailImmediately
        {
            get
            {
                return (Flags & LockFlags.FailImmediately) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= LockFlags.FailImmediately;
                }
                else
                {
                    Flags &= ~LockFlags.FailImmediately;
                }
            }
        }

        public static List<LockElement> ReadLockList(byte[] buffer, int offset, int lockCount)
        {
            List<LockElement> result = new List<LockElement>();
            for (int lockIndex = 0; lockIndex < lockCount; lockIndex++)
            {
                LockElement element = new LockElement(buffer, offset + lockIndex * StructureLength);
                result.Add(element);
            }
            return result;
        }

        public static void WriteLockList(byte[] buffer, int offset, List<LockElement> locks)
        {
            for (int lockIndex = 0; lockIndex < locks.Count; lockIndex++)
            {
                LockElement element = locks[lockIndex];
                element.WriteBytes(buffer, offset + lockIndex * StructureLength);
            }
        }
    }
}