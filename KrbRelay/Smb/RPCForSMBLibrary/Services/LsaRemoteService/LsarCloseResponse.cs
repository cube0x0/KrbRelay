/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// LsarClose Response (opnum 0)
/// </summary>
public class LsarCloseResponse
{
    private LsaHandle PolicyHandle;

    public LsarCloseResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        PolicyHandle = new LsaHandle();
        parser.ReadStructure(PolicyHandle);
    }
}