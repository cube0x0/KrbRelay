/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    /// <summary>
    /// [MS-NLMP] 2.2.2.10 - VERSION
    /// </summary>
    public class NTLMVersion
    {
        public const int Length = 8;
        public const byte NTLMSSP_REVISION_W2K3 = 0x0F;

        public byte ProductMajorVersion;
        public byte ProductMinorVersion;
        public ushort ProductBuild;

        // Reserved - 3 bytes
        public byte NTLMRevisionCurrent;

        public NTLMVersion(byte majorVersion, byte minorVersion, ushort build, byte ntlmRevisionCurrent)
        {
            ProductMajorVersion = majorVersion;
            ProductMinorVersion = minorVersion;
            ProductBuild = build;
            NTLMRevisionCurrent = ntlmRevisionCurrent;
        }

        public NTLMVersion(byte[] buffer, int offset)
        {
            ProductMajorVersion = ByteReader.ReadByte(buffer, offset + 0);
            ProductMinorVersion = ByteReader.ReadByte(buffer, offset + 1);
            ProductBuild = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            NTLMRevisionCurrent = ByteReader.ReadByte(buffer, offset + 7);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ByteWriter.WriteByte(buffer, offset + 0, ProductMajorVersion);
            ByteWriter.WriteByte(buffer, offset + 1, ProductMinorVersion);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, ProductBuild);
            ByteWriter.WriteByte(buffer, offset + 7, NTLMRevisionCurrent);
        }

        public override string ToString()
        {
            return String.Format("{0}.{1}.{2}", ProductMajorVersion, ProductMinorVersion, ProductBuild);
        }

        public static NTLMVersion WindowsXP
        {
            get
            {
                return new NTLMVersion(5, 1, 2600, NTLMSSP_REVISION_W2K3);
            }
        }

        public static NTLMVersion Server2003
        {
            get
            {
                return new NTLMVersion(5, 2, 3790, NTLMSSP_REVISION_W2K3);
            }
        }
    }
}