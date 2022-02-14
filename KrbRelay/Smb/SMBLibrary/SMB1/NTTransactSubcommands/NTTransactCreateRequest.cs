/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// NT_TRANSACT_CREATE Request
    /// </summary>
    public class NTTransactCreateRequest : NTTransactSubcommand
    {
        public const int ParametersFixedLength = 53;

        // Parameters:
        public NTCreateFlags Flags;

        public uint RootDirectoryFID;
        public AccessMask DesiredAccess;
        public long AllocationSize;
        public ExtendedFileAttributes ExtFileAttributes;
        public ShareAccess ShareAccess;
        public CreateDisposition CreateDisposition;
        public CreateOptions CreateOptions;

        // uint SecurityDescriptiorLength;
        // uint EALength;
        // uint NameLength;
        public ImpersonationLevel ImpersonationLevel;

        public SecurityFlags SecurityFlags;
        public string Name; // OEM / Unicode. NOT null terminated. (MUST be aligned to start on a 2-byte boundary from the start of the NT_Trans_Parameters)

        // Data:
        public SecurityDescriptor SecurityDescriptor;

        public List<FileFullEAEntry> ExtendedAttributes;

        public NTTransactCreateRequest()
        {
        }

        public NTTransactCreateRequest(byte[] parameters, byte[] data, bool isUnicode)
        {
            int parametersOffset = 0;
            Flags = (NTCreateFlags)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            RootDirectoryFID = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            DesiredAccess = (AccessMask)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            AllocationSize = LittleEndianReader.ReadInt64(parameters, ref parametersOffset);
            ExtFileAttributes = (ExtendedFileAttributes)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            ShareAccess = (ShareAccess)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            CreateDisposition = (CreateDisposition)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            CreateOptions = (CreateOptions)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            uint securityDescriptiorLength = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            uint eaLength = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            uint nameLength = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            ImpersonationLevel = (ImpersonationLevel)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            SecurityFlags = (SecurityFlags)ByteReader.ReadByte(parameters, ref parametersOffset);

            if (isUnicode)
            {
                parametersOffset++;
            }
            Name = SMB1Helper.ReadFixedLengthString(parameters, ref parametersOffset, isUnicode, (int)nameLength);
            if (securityDescriptiorLength > 0)
            {
                SecurityDescriptor = new SecurityDescriptor(data, 0);
            }
            ExtendedAttributes = FileFullEAInformation.ReadList(data, (int)securityDescriptiorLength);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            throw new NotImplementedException();
        }

        public override byte[] GetData()
        {
            throw new NotImplementedException();
        }

        public override NTTransactSubcommandName SubcommandName
        {
            get
            {
                return NTTransactSubcommandName.NT_TRANSACT_CREATE;
            }
        }
    }
}