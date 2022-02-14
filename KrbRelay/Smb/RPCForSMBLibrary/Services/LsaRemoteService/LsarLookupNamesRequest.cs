/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// LsarLookupNames Request (opnum 14)
/// </summary>
public class LsarLookupNamesRequest : IRPCRequest
{
    public LsaHandle handle;

    public NDRConformantArray<LsaUnicodeString> Names;
    public LsaTranslatedArray<LsaTranslatedSid> TranslatedSids;
    public ushort LookupLevel = 1;

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        //handle
        writer.WriteStructure(handle);

        writer.WriteUInt32((uint)Names.Count);
        // names array
        writer.WriteStructure(Names);

        //translated sids
        writer.WriteStructure(TranslatedSids);

        //level
        writer.WriteUInt16(LookupLevel);

        // mappedcount
        writer.WriteUInt32(0);
        return writer.GetBytes();
    }
}