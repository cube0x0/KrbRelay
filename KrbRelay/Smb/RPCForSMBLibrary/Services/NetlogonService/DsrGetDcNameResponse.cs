/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// DsrGetDcName Response (opnum 20)
/// </summary>
public class DsrGetDcNameResponse
{
    public NDRDomainControllerInfo DCInfo;

    public DsrGetDcNameResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        parser.ReadEmbeddedStructureFullPointer(ref DCInfo);
        parser.EndStructure();
    }
}