/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    public abstract class SMBAndXCommand : SMB1Command
    {
        public CommandName AndXCommand;
        public byte AndXReserved;
        public ushort AndXOffset;

        public SMBAndXCommand() : base()
        {
        }

        public SMBAndXCommand(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            AndXCommand = (CommandName)ByteReader.ReadByte(this.SMBParameters, 0);
            AndXReserved = ByteReader.ReadByte(this.SMBParameters, 1);
            AndXOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 2);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            ByteWriter.WriteByte(this.SMBParameters, 0, (byte)AndXCommand);
            ByteWriter.WriteByte(this.SMBParameters, 1, AndXReserved);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 2, AndXOffset);
            return base.GetBytes(isUnicode);
        }

        public static void WriteAndXOffset(byte[] buffer, int commandOffset, ushort AndXOffset)
        {
            // 3 preceding bytes: WordCount, AndXCommand and AndXReserved
            LittleEndianWriter.WriteUInt16(buffer, commandOffset + 3, AndXOffset);
        }
    }
}