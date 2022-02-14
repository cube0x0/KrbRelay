/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_WRITE_ANDX Response
    /// SMB 1.0: The 2 reserved bytes at offset 8 become CountHigh (used when the CAP_LARGE_WRITEX capability has been negotiated)
    /// </summary>
    public class WriteAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 12;

        // Parameters:
        //CommandName AndXCommand;
        //byte AndXReserved;
        //ushort AndXOffset;
        public uint Count; // The number of bytes written to the file, 2 bytes + 2 'CountHigh' bytes

        public ushort Available;
        public ushort Reserved;

        public WriteAndXResponse() : base()
        { }

        public WriteAndXResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            Count = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            Available = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);
            ushort countHigh = LittleEndianConverter.ToUInt16(this.SMBParameters, 8);
            Reserved = LittleEndianConverter.ToUInt16(this.SMBParameters, 10);

            Count |= (uint)(countHigh << 16);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            ushort counthHigh = (ushort)(Count >> 16);

            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, (ushort)(Count & 0xFFFF));
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, Available);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 8, counthHigh);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 10, Reserved);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_WRITE_ANDX;
            }
        }
    }
}