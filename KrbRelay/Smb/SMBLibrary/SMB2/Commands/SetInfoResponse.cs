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
    /// SMB2 SET_INFO Response
    /// </summary>
    public class SetInfoResponse : SMB2Command
    {
        public const int DeclaredSize = 2;

        private ushort StructureSize;

        public SetInfoResponse() : base(SMB2CommandName.SetInfo)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public SetInfoResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
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