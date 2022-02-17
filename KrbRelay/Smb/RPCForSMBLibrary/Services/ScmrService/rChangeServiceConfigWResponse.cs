using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rChangeServiceConfigW   Response (opnum 11)
/// </summary>
public class rChangeServiceConfigWResponse
{
    public uint lpdwTagId;

    public rChangeServiceConfigWResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        lpdwTagId = parser.ReadUInt32();
        parser.EndStructure();
    }
}