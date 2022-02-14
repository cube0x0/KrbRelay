/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_ECHO
    /// </summary>
    public class EchoResponse : SMB1Command
    {
        public const int ParametersLength = 2;

        // Parameters
        public ushort SequenceNumber;

        public EchoResponse() : base()
        {
        }

        public EchoResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            SequenceNumber = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, SequenceNumber);

            return base.GetBytes(isUnicode);
        }

        public byte[] Data
        {
            get
            {
                return this.SMBData;
            }
            set
            {
                this.SMBData = value;
            }
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_ECHO;
            }
        }
    }
}