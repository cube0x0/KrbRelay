/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// p_syntax_id_t
    /// </summary>
    public struct SyntaxID
    {
        public const int Length = 20;

        public Guid InterfaceUUID; // if_uuid
        public uint InterfaceVersion; // if_version

        public SyntaxID(Guid interfaceUUID, uint interfaceVersion)
        {
            InterfaceUUID = interfaceUUID;
            InterfaceVersion = interfaceVersion;
        }

        public SyntaxID(byte[] buffer, int offset)
        {
            InterfaceUUID = LittleEndianConverter.ToGuid(buffer, offset + 0);
            InterfaceVersion = LittleEndianConverter.ToUInt32(buffer, offset + 16);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteGuid(buffer, offset + 0, InterfaceUUID);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, InterfaceVersion);
        }

        public override bool Equals(object obj)
        {
            if (obj is SyntaxID)
            {
                return this.InterfaceUUID.Equals(((SyntaxID)obj).InterfaceUUID) && this.InterfaceVersion.Equals(((SyntaxID)obj).InterfaceVersion);
            }
            return false;
        }

        public override int GetHashCode()
        {
            return InterfaceUUID.GetHashCode() * InterfaceVersion.GetHashCode();
        }
    }
}