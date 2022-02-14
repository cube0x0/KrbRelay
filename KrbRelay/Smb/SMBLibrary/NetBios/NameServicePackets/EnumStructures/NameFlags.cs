/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.NetBios
{
    public enum OwnerNodeType : byte
    {
        BNode = 0x00,
        PNode = 0x01,
        MNode = 0x10,
    }

    public struct NameFlags // ushort
    {
        public const int Length = 2;

        public OwnerNodeType NodeType;
        public bool WorkGroup;

        public static explicit operator ushort(NameFlags nameFlags)
        {
            ushort value = (ushort)(((byte)nameFlags.NodeType) << 13);
            if (nameFlags.WorkGroup)
            {
                value |= 0x8000;
            }
            return value;
        }

        public static explicit operator NameFlags(ushort value)
        {
            NameFlags result = new NameFlags();
            result.NodeType = (OwnerNodeType)((value >> 13) & 0x3);
            result.WorkGroup = (value & 0x8000) > 0;
            return result;
        }
    }
}