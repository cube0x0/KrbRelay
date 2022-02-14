/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;

/// <summary>
/// NetrRemoteTOD Request (Opnum 28)
/// </summary>
public class NetrServerStatisticsGetRequest : IRPCRequest
{
    public string ServerName;
    public string Service;
    public uint Level;
    public uint Options;

    public NetrServerStatisticsGetRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.BeginStructure();
        writer.WriteTopLevelUnicodeStringPointer(ServerName.StartsWith("\\\\") ? ServerName : "\\\\" + ServerName);
        writer.WriteTopLevelUnicodeStringPointer(Service);
        writer.WriteUInt32(Level);
        writer.WriteUInt32(Options);
        writer.EndStructure();
        return writer.GetBytes();
    }
}