using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrEnumerateDomainsInSamServer Response (opnum 06)
/// TODO: FIX READING BUG
/// </summary>
public class samrEnumerateDomainsInSamServerResponse
{
    public uint EnumerationContext;
    public SAMPR_ENUMERATION_BUFFER Buffer;
    public uint CountReturned;

    public samrEnumerateDomainsInSamServerResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        EnumerationContext = parser.ReadUInt32();
        Buffer = new SAMPR_ENUMERATION_BUFFER();
        parser.ReadStructure(Buffer);
        CountReturned = parser.ReadUInt32();
    }
}