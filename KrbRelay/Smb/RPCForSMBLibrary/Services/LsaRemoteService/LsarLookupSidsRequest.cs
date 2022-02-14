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
/// LsarLookupSids Request (opnum 15)
/// </summary>
public class LsarLookupSidsRequest : IRPCRequest
{
    public LsaHandle handle;

    public ushort level = 1;
    public LsaSIDEnumBuffer SIDEnumBuffer;
    public LsaTranslatedArray<LsaTranslatedName> TranslatedNames;

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        //handle
        writer.WriteStructure(handle);
        // sid array
        writer.WriteStructure(SIDEnumBuffer);

        //translated names
        writer.WriteStructure(TranslatedNames);

        //level
        writer.WriteUInt16(level);

        // mappedcount
        writer.WriteUInt32(0);
        return writer.GetBytes();
    }
}