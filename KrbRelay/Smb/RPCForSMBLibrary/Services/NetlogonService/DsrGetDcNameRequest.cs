/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;

/// <summary>
/// DsrGetDcName Request (opnum 20)
/// </summary>
public class DsrGetDcNameRequest : IRPCRequest
{
    public string ServerName;
    public string DomainName;
    public string SiteName;
    public uint Flags;

    public DsrGetDcNameRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(ServerName);
        writer.WriteTopLevelUnicodeStringPointer(DomainName);
        //guid
        writer.WriteUInt32(0);
        writer.WriteTopLevelUnicodeStringPointer(SiteName);
        writer.WriteUInt32(Flags);
        return writer.GetBytes();
    }
}