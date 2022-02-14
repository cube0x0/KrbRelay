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
    /// NetrShareEnum Response (opnum 15)
    /// </summary>
    public class NetrShareEnumResponse
    {
        public ShareEnum InfoStruct;
        public uint TotalEntries; // The total number of entries that could have been enumerated if the buffer had been big enough to hold all the entries
        public uint ResumeHandle;
        public Win32Error Result;

        public NetrShareEnumResponse()
        {
        }

        public NetrShareEnumResponse(byte[] buffer)
        {
            NDRParser parser = new NDRParser(buffer);
            InfoStruct = new ShareEnum(parser);
            TotalEntries = parser.ReadUInt32();
            ResumeHandle = parser.ReadUInt32();
            Result = (Win32Error)parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            NDRWriter writer = new NDRWriter();
            writer.WriteStructure(InfoStruct);
            writer.WriteUInt32(TotalEntries);
            writer.WriteUInt32(ResumeHandle);
            writer.WriteUInt32((uint)Result);

            return writer.GetBytes();
        }
    }
}