/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;

/// <summary>
/// EfsRpcOpenFileRaw Request (opnum 0)
/// </summary>
public class EfsRpcOpenFileRawRequest : IRPCRequest
{
    public string FileName;
    public int Flags;

    public EfsRpcOpenFileRawRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteUnicodeString(FileName);
        writer.WriteUInt32((uint)Flags);

        return writer.GetBytes();
    }
}