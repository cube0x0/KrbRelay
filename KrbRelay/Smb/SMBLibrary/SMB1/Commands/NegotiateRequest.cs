/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_NEGOTIATE Request
    /// </summary>
    public class NegotiateRequest : SMB1Command
    {
        public const int SupportedBufferFormat = 0x02;

        // Data:
        public List<string> Dialects = new List<string>();

        public NegotiateRequest() : base()
        {
        }

        public NegotiateRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            int dataOffset = 0;
            while (dataOffset < SMBData.Length)
            {
                byte bufferFormat = ByteReader.ReadByte(SMBData, ref dataOffset);
                if (bufferFormat != SupportedBufferFormat)
                {
                    throw new InvalidDataException("Unsupported Buffer Format");
                }
                string dialect = ByteReader.ReadNullTerminatedAnsiString(SMBData, dataOffset);
                Dialects.Add(dialect);
                dataOffset += dialect.Length + 1;
            }
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            int length = 0;
            foreach (string dialect in Dialects)
            {
                length += 1 + dialect.Length + 1;
            }

            SMBParameters = new byte[0];
            SMBData = new byte[length];
            int offset = 0;
            foreach (string dialect in Dialects)
            {
                ByteWriter.WriteByte(SMBData, offset, 0x02);
                ByteWriter.WriteAnsiString(SMBData, offset + 1, dialect, dialect.Length);
                ByteWriter.WriteByte(SMBData, offset + 1 + dialect.Length, 0x00);
                offset += 1 + dialect.Length + 1;
            }
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