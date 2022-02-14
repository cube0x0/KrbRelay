/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    /// <summary>
    /// NetrShareEnum Request (opnum 15)
    /// </summary>
    public class NetrShareEnumRequest
    {
        public string ServerName;
        public ShareEnum InfoStruct;
        public uint PreferedMaximumLength; // Preferred maximum length, in bytes, of the returned data
        public uint ResumeHandle;

        public NetrShareEnumRequest()
        {
        }

        public NetrShareEnumRequest(byte[] buffer)
        {
            NDRParser parser = new NDRParser(buffer);
            ServerName = parser.ReadTopLevelUnicodeStringPointer();
            InfoStruct = new ShareEnum(parser);
            PreferedMaximumLength = parser.ReadUInt32();
            ResumeHandle = parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            NDRWriter writer = new NDRWriter();
            writer.WriteTopLevelUnicodeStringPointer(ServerName);
            writer.WriteStructure(InfoStruct);
            writer.WriteUInt32(PreferedMaximumLength);
            writer.WriteUInt32(ResumeHandle);

            return writer.GetBytes();
        }
    }
}