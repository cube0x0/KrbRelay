using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// SamrConnect Response (opnum 0)
/// </summary>
public class SamrConnectResponse
{
    public SamprHandle SamrHandle;

    public SamrConnectResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        SamrHandle = new SamprHandle();
        parser.ReadStructure(SamrHandle);
    }
}