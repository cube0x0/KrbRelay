using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rControlService   Response (opnum 01)
/// </summary>
public class rControlServiceResponse
{
    public SERVICE_STATUS lpServiceStatus;

    public rControlServiceResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        lpServiceStatus = new SERVICE_STATUS();
        parser.ReadStructure(lpServiceStatus);
        parser.EndStructure();
    }
}