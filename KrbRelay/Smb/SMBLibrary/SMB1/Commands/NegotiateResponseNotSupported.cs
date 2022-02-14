/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_NEGOTIATE Response
    /// </summary>
    public class NegotiateResponseNotSupported : SMB1Command
    {
        public const int ParametersLength = 2;
        public const ushort DialectsNotSupported = 0xFFFF;

        public NegotiateResponseNotSupported() : base()
        {
        }

        public NegotiateResponseNotSupported(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            throw new NotImplementedException();
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, DialectsNotSupported);

            this.SMBData = new byte[0];

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_NEGOTIATE;
            }
        }
    }
}