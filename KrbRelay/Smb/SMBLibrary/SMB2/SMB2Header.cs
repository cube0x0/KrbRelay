/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB2
{
    public class SMB2Header
    {
        public const int Length = 64;
        public const int SignatureOffset = 48;

        public static readonly byte[] ProtocolSignature = new byte[] { 0xFE, 0x53, 0x4D, 0x42 };

        private byte[] ProtocolId; // 4 bytes, 0xFE followed by "SMB"
        private ushort StructureSize;
        public ushort CreditCharge;
        public NTStatus Status;
        public SMB2CommandName Command;
        public ushort Credits; // CreditRequest or CreditResponse (The number of credits granted to the client)
        public SMB2PacketHeaderFlags Flags;
        public uint NextCommand; // offset in bytes
        public ulong MessageID;
        public uint Reserved; // Sync
        public uint TreeID;   // Sync
        public ulong AsyncID; // Async
        public ulong SessionID;
        public byte[] Signature; // 16 bytes (present if SMB2_FLAGS_SIGNED is set)

        public SMB2Header(SMB2CommandName commandName)
        {
            ProtocolId = ProtocolSignature;
            StructureSize = Length;
            Command = commandName;
            Signature = new byte[16];
        }

        public SMB2Header(byte[] buffer, int offset)
        {
            ProtocolId = ByteReader.ReadBytes(buffer, offset + 0, 4);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + 4);
            CreditCharge = LittleEndianConverter.ToUInt16(buffer, offset + 6);
            Status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
            Command = (SMB2CommandName)LittleEndianConverter.ToUInt16(buffer, offset + 12);
            Credits = LittleEndianConverter.ToUInt16(buffer, offset + 14);
            Flags = (SMB2PacketHeaderFlags)LittleEndianConverter.ToUInt32(buffer, offset + 16);
            NextCommand = LittleEndianConverter.ToUInt32(buffer, offset + 20);
            MessageID = LittleEndianConverter.ToUInt64(buffer, offset + 24);
            if ((Flags & SMB2PacketHeaderFlags.AsyncCommand) > 0)
            {
                AsyncID = LittleEndianConverter.ToUInt64(buffer, offset + 32);
            }
            else
            {
                Reserved = LittleEndianConverter.ToUInt32(buffer, offset + 32);
                TreeID = LittleEndianConverter.ToUInt32(buffer, offset + 36);
            }
            SessionID = LittleEndianConverter.ToUInt64(buffer, offset + 40);
            if ((Flags & SMB2PacketHeaderFlags.Signed) > 0)
            {
                Signature = ByteReader.ReadBytes(buffer, offset + 48, 16);
            }
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteBytes(buffer, offset + 0, ProtocolId);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, CreditCharge);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, (uint)Status);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, (ushort)Command);
            LittleEndianWriter.WriteUInt16(buffer, offset + 14, Credits);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, (uint)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 20, NextCommand);
            LittleEndianWriter.WriteUInt64(buffer, offset + 24, MessageID);
            if ((Flags & SMB2PacketHeaderFlags.AsyncCommand) > 0)
            {
                LittleEndianWriter.WriteUInt64(buffer, offset + 32, AsyncID);
            }
            else
            {
                LittleEndianWriter.WriteUInt32(buffer, offset + 32, Reserved);
                LittleEndianWriter.WriteUInt32(buffer, offset + 36, TreeID);
            }
            LittleEndianWriter.WriteUInt64(buffer, offset + 40, SessionID);
            if ((Flags & SMB2PacketHeaderFlags.Signed) > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + 48, Signature);
            }
        }

        public bool IsResponse
        {
            get
            {
                return (Flags & SMB2PacketHeaderFlags.ServerToRedir) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.ServerToRedir;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.ServerToRedir;
                }
            }
        }

        public bool IsAsync
        {
            get
            {
                return (Flags & SMB2PacketHeaderFlags.AsyncCommand) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.AsyncCommand;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.AsyncCommand;
                }
            }
        }

        public bool IsRelatedOperations
        {
            get
            {
                return (Flags & SMB2PacketHeaderFlags.RelatedOperations) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.RelatedOperations;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.RelatedOperations;
                }
            }
        }

        public bool IsSigned
        {
            get
            {
                return (Flags & SMB2PacketHeaderFlags.Signed) > 0;
            }
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.Signed;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.Signed;
                }
            }
        }

        public static bool IsValidSMB2Header(byte[] buffer)
        {
            if (buffer.Length >= 4)
            {
                byte[] protocol = ByteReader.ReadBytes(buffer, 0, 4);
                return ByteUtils.AreByteArraysEqual(protocol, ProtocolSignature);
            }
            return false;
        }
    }
}