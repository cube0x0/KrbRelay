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
    /// NetrShareGetInfo Response (opnum 16)
    /// </summary>
    public class NetrShareGetInfoResponse
    {
        public ShareInfo InfoStruct;
        public Win32Error Result;

        public NetrShareGetInfoResponse()
        {
        }

        public NetrShareGetInfoResponse(byte[] buffer)
        {
            NDRParser parser = new NDRParser(buffer);
            InfoStruct = new ShareInfo(parser);
            Result = (Win32Error)parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            NDRWriter writer = new NDRWriter();
            writer.WriteStructure(InfoStruct);
            writer.WriteUInt32((uint)Result);

            return writer.GetBytes();
        }
    }
}