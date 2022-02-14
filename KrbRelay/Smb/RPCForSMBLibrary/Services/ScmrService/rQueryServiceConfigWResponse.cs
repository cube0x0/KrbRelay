using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rQueryServiceConfigW   Response (opnum 17)
/// </summary>
public class rQueryServiceConfigWResponse
{
    public QUERY_SERVICE_CONFIGW lpServiceConfig;
    public uint pcbBytesNeeded;

    public rQueryServiceConfigWResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        lpServiceConfig = new QUERY_SERVICE_CONFIGW();
        parser.ReadStructure(lpServiceConfig);
        pcbBytesNeeded = parser.ReadUInt32();
        parser.EndStructure();
    }
}