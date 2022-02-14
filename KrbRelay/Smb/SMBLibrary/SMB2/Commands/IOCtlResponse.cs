/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 IOCTL Request
    /// </summary>
    public class IOCtlResponse : SMB2Command
    {
        public const int FixedLength = 48;
        public const int DeclaredSize = 49;

        private ushort StructureSize;
        public ushort Reserved;
        public uint CtlCode;
        public FileID FileId;
        private uint InputOffset;
        private uint InputCount;
        private uint OutputOffset;
        private uint OutputCount;
        public uint Flags;
        public uint Reserved2;
        public byte[] Input = new byte[0];
        public byte[] Output = new byte[0];

        public IOCtlResponse() : base(SMB2CommandName.IOCtl)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public IOCtlResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            CtlCode = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 8);
            InputOffset = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 24);
            InputCount = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 28);
            OutputOffset = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 32);
            OutputCount = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 36);
            Flags = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 40);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 44);
            Input = ByteReader.ReadBytes(buffer, offset + (int)InputOffset, (int)InputCount);
            Output = ByteReader.ReadBytes(buffer, offset + (int)OutputOffset, (int)OutputCount);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            InputOffset = 0;
            InputCount = (uint)Input.Length;
            OutputOffset = 0;
            OutputCount = (uint)Output.Length;
            if (Input.Length > 0)
            {
                InputOffset = SMB2Header.Length + FixedLength;
            }
            // MS-SMB2: the output offset MUST be set to InputOffset + InputCount rounded up to a multiple of 8
            int paddedInputLength = (int)Math.Ceiling((double)Input.Length / 8) * 8;
            if (Output.Length > 0)
            {
                OutputOffset = SMB2Header.Length + FixedLength + (uint)paddedInputLength;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, CtlCode);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, InputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, InputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, OutputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, OutputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, Reserved2);
            if (Input.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedLength, Input);
            }
            if (Output.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedLength + paddedInputLength, Output);
            }
        }

        public override int CommandLength
        {
            get
            {
                int paddedInputLength = (int)Math.Ceiling((double)Input.Length / 8) * 8;
                return FixedLength + paddedInputLength + Output.Length;
            }
        }
    }
}