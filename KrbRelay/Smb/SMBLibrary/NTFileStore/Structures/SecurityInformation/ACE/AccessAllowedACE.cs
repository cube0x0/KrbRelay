/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-DTYP] ACCESS_ALLOWED_ACE
    /// </summary>
    public class AccessAllowedACE : ACE
    {
        public const int FixedLength = 8;

        public AceHeader Header;
        public AccessMask Mask;
        public SID Sid;

        public AccessAllowedACE()
        {
            Header = new AceHeader();
            Header.AceType = AceType.ACCESS_ALLOWED_ACE_TYPE;
        }

        public AccessAllowedACE(byte[] buffer, int offset)
        {
            Header = new AceHeader(buffer, offset + 0);
            Mask = (AccessMask)LittleEndianConverter.ToUInt32(buffer, offset + 4);
            Sid = new SID(buffer, offset + 8);
        }

        public override void WriteBytes(byte[] buffer, ref int offset)
        {
            Header.AceSize = (ushort)this.Length;
            Header.WriteBytes(buffer, ref offset);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)Mask);
            Sid.WriteBytes(buffer, ref offset);
        }

        public override int Length
        {
            get
            {
                return FixedLength + Sid.Length;
            }
        }
    }
}