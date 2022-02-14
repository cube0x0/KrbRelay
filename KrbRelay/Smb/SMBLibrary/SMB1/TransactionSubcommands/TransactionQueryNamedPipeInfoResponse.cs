/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_QUERY_NMPIPE_INFO Response
    /// </summary>
    public class TransactionQueryNamedPipeInfoResponse : TransactionSubcommand
    {
        public const int ParametersLength = 0;

        // Data:
        public ushort OutputBufferSize;

        public ushort InputBufferSize;
        public byte MaximumInstances;
        public byte CurrentInstances;
        public byte PipeNameLength;
        public string PipeName; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public TransactionQueryNamedPipeInfoResponse() : base()
        { }

        public TransactionQueryNamedPipeInfoResponse(byte[] data, bool isUnicode) : base()
        {
            OutputBufferSize = LittleEndianConverter.ToUInt16(data, 0);
            InputBufferSize = LittleEndianConverter.ToUInt16(data, 2);
            MaximumInstances = ByteReader.ReadByte(data, 4);
            CurrentInstances = ByteReader.ReadByte(data, 5);
            PipeNameLength = ByteReader.ReadByte(data, 6);
            // Note: Trans_Parameters is aligned to 4 byte boundary
            PipeName = SMB1Helper.ReadSMBString(data, 8, isUnicode);
        }

        public override byte[] GetData(bool isUnicode)
        {
            int length = 8;
            if (isUnicode)
            {
                length += PipeName.Length * 2 + 2;
            }
            else
            {
                length += PipeName.Length + 1;
            }
            byte[] data = new byte[length];
            LittleEndianWriter.WriteUInt16(data, 0, OutputBufferSize);
            LittleEndianWriter.WriteUInt16(data, 2, InputBufferSize);
            ByteWriter.WriteByte(data, 4, MaximumInstances);
            ByteWriter.WriteByte(data, 5, CurrentInstances);
            ByteWriter.WriteByte(data, 6, PipeNameLength);
            SMB1Helper.WriteSMBString(data, 8, isUnicode, PipeName);
            return data;
        }

        public override TransactionSubcommandName SubcommandName
        {
            get
            {
                return TransactionSubcommandName.TRANS_QUERY_NMPIPE_INFO;
            }
        }
    }
}