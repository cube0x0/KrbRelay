using SMBLibrary.RPC;

/// <summary>
/// samrLookupDomainInSamServer Response (opnum 05)
/// </summary>
public class samrLookupDomainInSamServerResponse
{
    public uint DomainId;

    public samrLookupDomainInSamServerResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        DomainId = parser.ReadUInt32();
    }
}