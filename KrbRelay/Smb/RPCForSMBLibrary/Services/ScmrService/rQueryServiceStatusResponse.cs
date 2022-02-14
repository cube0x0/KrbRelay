using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rQueryServiceStatus   Response (opnum 06)
/// </summary>
public class rQueryServiceStatusResponse
{
    public SERVICE_STATUS lpServiceStatus;

    public rQueryServiceStatusResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        lpServiceStatus = new SERVICE_STATUS();
        parser.ReadStructure(lpServiceStatus);
        parser.EndStructure();
    }
}