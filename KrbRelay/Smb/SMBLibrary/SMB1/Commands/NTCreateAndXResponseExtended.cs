/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB_COM_NT_CREATE_ANDX Extended Response
    /// </summary>
    public class NTCreateAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 100;

        // [MS-SMB] Section 2.2.4.9.2 and Note <49>:
        // Windows-based SMB servers send 50 (0x32) words in the extended response although they set the WordCount field to 0x2A.
        public const int DeclaredParametersLength = 84;

        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public OpLockLevel OpLockLevel;

        public ushort FID;
        public CreateDisposition CreateDisposition;
        public DateTime? CreateTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? LastChangeTime;
        public ExtendedFileAttributes ExtFileAttributes;
        public long AllocationSize;
        public long EndOfFile;
        public ResourceType ResourceType;
        public ushort NMPipeStatus_or_FileStatusFlags;
        public bool Directory;
        public Guid VolumeGuid;
        public ulong FileID;
        public AccessMask MaximalAccessRights;
        public AccessMask GuestMaximalAccessRights;

        public NTCreateAndXResponseExtended() : base()
        {
        }

        public NTCreateAndXResponseExtended(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            int parametersOffset = 4;
            OpLockLevel = (OpLockLevel)ByteReader.ReadByte(SMBParameters, ref parametersOffset);
            FID = LittleEndianReader.ReadUInt16(SMBParameters, ref parametersOffset);
            CreateDisposition = (CreateDisposition)LittleEndianReader.ReadUInt32(SMBParameters, ref parametersOffset);
            CreateTime = FileTimeHelper.ReadNullableFileTime(SMBParameters, ref parametersOffset);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(SMBParameters, ref parametersOffset);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(SMBParameters, ref parametersOffset);
            LastChangeTime = FileTimeHelper.ReadNullableFileTime(SMBParameters, ref parametersOffset);
            ExtFileAttributes = (ExtendedFileAttributes)LittleEndianReader.ReadUInt32(SMBParameters, ref parametersOffset);
            AllocationSize = LittleEndianReader.ReadInt64(SMBParameters, ref parametersOffset);
            EndOfFile = LittleEndianReader.ReadInt64(SMBParameters, ref parametersOffset);
            ResourceType = (ResourceType)LittleEndianReader.ReadUInt16(SMBParameters, ref parametersOffset);
            NMPipeStatus_or_FileStatusFlags = LittleEndianReader.ReadUInt16(SMBParameters, ref parametersOffset);
            Directory = (ByteReader.ReadByte(SMBParameters, ref parametersOffset) > 0);
            VolumeGuid = LittleEndianReader.ReadGuid(SMBParameters, ref parametersOffset);
            FileID = LittleEndianReader.ReadUInt64(SMBParameters, ref parametersOffset);
            MaximalAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(SMBParameters, ref parametersOffset);
            GuestMaximalAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(SMBParameters, ref parametersOffset);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            SMBParameters = new byte[ParametersLength];
            int parametersOffset = 4;
            ByteWriter.WriteByte(SMBParameters, ref parametersOffset, (byte)OpLockLevel);
            LittleEndianWriter.WriteUInt16(SMBParameters, ref parametersOffset, FID);
            LittleEndianWriter.WriteUInt32(SMBParameters, ref parametersOffset, (uint)CreateDisposition);
            FileTimeHelper.WriteFileTime(SMBParameters, ref parametersOffset, CreateTime);
            FileTimeHelper.WriteFileTime(SMBParameters, ref parametersOffset, LastAccessTime);
            FileTimeHelper.WriteFileTime(SMBParameters, ref parametersOffset, LastWriteTime);
            FileTimeHelper.WriteFileTime(SMBParameters, ref parametersOffset, LastChangeTime);
            LittleEndianWriter.WriteUInt32(SMBParameters, ref parametersOffset, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteInt64(SMBParameters, ref parametersOffset, AllocationSize);
            LittleEndianWriter.WriteInt64(SMBParameters, ref parametersOffset, EndOfFile);
            LittleEndianWriter.WriteUInt16(SMBParameters, ref parametersOffset, (ushort)ResourceType);
            LittleEndianWriter.WriteUInt16(SMBParameters, ref parametersOffset, NMPipeStatus_or_FileStatusFlags);
            ByteWriter.WriteByte(SMBParameters, ref parametersOffset, Convert.ToByte(Directory));
            LittleEndianWriter.WriteGuid(SMBParameters, ref parametersOffset, VolumeGuid);
            LittleEndianWriter.WriteUInt64(SMBParameters, ref parametersOffset, FileID);
            LittleEndianWriter.WriteUInt32(SMBParameters, ref parametersOffset, (uint)MaximalAccessRights);
            LittleEndianWriter.WriteUInt32(SMBParameters, ref parametersOffset, (uint)GuestMaximalAccessRights);
            return base.GetBytes(isUnicode);
        }

        public NamedPipeStatus NMPipeStatus
        {
            get
            {
                return new NamedPipeStatus(NMPipeStatus_or_FileStatusFlags);
            }
            set
            {
                NMPipeStatus_or_FileStatusFlags = value.ToUInt16();
            }
        }

        public FileStatusFlags FileStatusFlags
        {
            get
            {
                return (FileStatusFlags)NMPipeStatus_or_FileStatusFlags;
            }
            set
            {
                NMPipeStatus_or_FileStatusFlags = (ushort)value;
            }
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_NT_CREATE_ANDX;
            }
        }
    }
}