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
    /// SMB2 IOCTL Request
    /// </summary>
    public class IOCtlRequest : SMB2Command
    {
        public const int FixedLength = 56;
        public const int DeclaredSize = 57;

        private ushort StructureSize;
        public ushort Reserved;
        public uint CtlCode;
        public FileID FileId;
        private uint InputOffset;
        private uint InputCount;
        public uint MaxInputResponse;
        private uint OutputOffset;
        private uint OutputCount;
        public uint MaxOutputResponse;
        public IOCtlRequestFlags Flags;
        public uint Reserved2;
        public byte[] Input = new byte[0];
        public byte[] Output = new byte[0];

        public IOCtlRequest() : base(SMB2CommandName.IOCtl)
        {
            StructureSize = DeclaredSize;
        }

        public IOCtlRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            CtlCode = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            FileId = new FileID(buffer, offset + SMB2Header.Length + 8);
            InputOffset = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 24);
            InputCount = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 28);
            MaxInputResponse = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 32);
            OutputOffset = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 36);
            OutputCount = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 40);
            MaxOutputResponse = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 44);
            Flags = (IOCtlRequestFlags)LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 48);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 52);
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
            if (Output.Length > 0)
            {
                OutputOffset = SMB2Header.Length + FixedLength + (uint)Input.Length;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, CtlCode);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, InputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, InputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, MaxInputResponse);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, OutputOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, OutputCount);
            LittleEndianWriter.WriteUInt32(buffer, offset + 44, MaxOutputResponse);
            LittleEndianWriter.WriteUInt32(buffer, offset + 48, (uint)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 52, Reserved2);
            if (Input.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedLength, Input);
            }
            if (Output.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedLength + Input.Length, Output);
            }
        }

        public bool IsFSCtl
        {
            get
            {
                return (Flags & IOCtlRequestFlags.IsFSCtl) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= IOCtlRequestFlags.IsFSCtl;
                }
                else
                {
                    Flags &= ~IOCtlRequestFlags.IsFSCtl;
                }
            }
        }

        public override int CommandLength
        {
            get
            {
                return FixedLength + Input.Length + Output.Length;
            }
        }
    }
}