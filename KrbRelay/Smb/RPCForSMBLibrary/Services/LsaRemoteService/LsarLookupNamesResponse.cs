/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// LsarLookupNames Response (opnum 14)
/// </summary>
public class LsarLookupNamesResponse
{
    public LsaReferencedDomainList DomainList;
    public LsaSIDEnumBuffer SIDEnumBuffer;
    public LsaTranslatedArray<LsaTranslatedSid> TranslatedNames;
    public uint Count;

    public LsarLookupNamesResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        DomainList = new LsaReferencedDomainList();

        parser.BeginStructure();
        parser.ReadEmbeddedStructureFullPointer(ref DomainList);
        parser.EndStructure();

        TranslatedNames = new LsaTranslatedArray<LsaTranslatedSid>();
        parser.ReadStructure(TranslatedNames);

        Count = parser.ReadUInt32();
    }
}