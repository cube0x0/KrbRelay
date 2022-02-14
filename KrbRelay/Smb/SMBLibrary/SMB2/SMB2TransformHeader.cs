/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// Used by the client or server when sending encrypted messages. only valid for the SMB 3.x dialect family.
    /// </summary>
    public class SMB2TransformHeader
    {
        public const int Length = 52;
        public const int SignatureLength = 16;
        public const int NonceLength = 16;

        private const int NonceStartOffset = 20;

        public static readonly byte[] ProtocolSignature = new byte[] { 0xFD, 0x53, 0x4D, 0x42 };

        private byte[] ProtocolId; // 4 bytes, 0xFD followed by "SMB"
        public byte[] Signature; // 16 bytes
        public byte[] Nonce; // 16 bytes
        public uint OriginalMessageSize;
        public ushort Reserved;
        public SMB2TransformHeaderFlags Flags; // EncryptionAlgorithm in SMB 3.0 / 3.0.2 where the only possible value is SMB2_ENCRYPTION_AES128_CCM = 0x0001
        public ulong SessionId;

        public SMB2TransformHeader()
        {
            ProtocolId = ProtocolSignature;
        }

        public SMB2TransformHeader(byte[] buffer, int offset)
        {
            ProtocolId = ByteReader.ReadBytes(buffer, offset + 0, 4);
            Signature = ByteReader.ReadBytes(buffer, offset + 4, SignatureLength);
            Nonce = ByteReader.ReadBytes(buffer, offset + 20, NonceLength);
            OriginalMessageSize = LittleEndianConverter.ToUInt32(buffer, offset + 36);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + 40);
            Flags = (SMB2TransformHeaderFlags)LittleEndianConverter.ToUInt16(buffer, offset + 42);
            SessionId = LittleEndianConverter.ToUInt64(buffer, offset + 44);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteBytes(buffer, offset + 0, ProtocolId);
            ByteWriter.WriteBytes(buffer, offset + 4, Signature);
            WriteAssociatedData(buffer, offset + 20);
        }

        private void WriteAssociatedData(byte[] buffer, int offset)
        {
            ByteWriter.WriteBytes(buffer, offset + 0, Nonce);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, OriginalMessageSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 20, Reserved);
            LittleEndianWriter.WriteUInt16(buffer, offset + 22, (ushort)Flags);
            LittleEndianWriter.WriteUInt64(buffer, offset + 24, SessionId);
        }

        public byte[] GetAssociatedData()
        {
            byte[] buffer = new byte[Length - NonceStartOffset];
            WriteAssociatedData(buffer, 0);
            return buffer;
        }

        public static bool IsTransformHeader(byte[] buffer, int offset)
        {
            byte[] protocolId = ByteReader.ReadBytes(buffer, offset + 0, 4);
            return ByteUtils.AreByteArraysEqual(ProtocolSignature, protocolId);
        }
    }
}