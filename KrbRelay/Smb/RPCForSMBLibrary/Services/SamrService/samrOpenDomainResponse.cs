using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrOpenDomain Response (opnum 07)
/// </summary>
public class samrOpenDomainResponse
{
    public SamprHandle DomainHandle;

    public samrOpenDomainResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        DomainHandle = new SamprHandle();
        parser.ReadStructure(DomainHandle);
    }
}