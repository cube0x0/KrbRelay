using SMBLibrary.RPC;

/// <summary>
/// rStartServiceW   Response (opnum 19)
/// </summary>
public class rStartServiceWResponse
{
    //public SERVICE_STATUS lpServiceStatus;

    public rStartServiceWResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        //parser.BeginStructure();
        //lpServiceStatus = new SERVICE_STATUS();
        //parser.ReadStructure(lpServiceStatus);
        //parser.EndStructure();
    }
}