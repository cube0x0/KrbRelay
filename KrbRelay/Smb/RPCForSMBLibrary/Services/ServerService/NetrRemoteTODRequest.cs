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
public class NetrRemoteTODRequest : IRPCRequest
{
    public string ServerName;

    public NetrRemoteTODRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.BeginStructure();
        writer.WriteTopLevelUnicodeStringPointer(ServerName.StartsWith("\\\\") ? ServerName : "\\\\" + ServerName);
        writer.EndStructure();
        return writer.GetBytes();
    }
}