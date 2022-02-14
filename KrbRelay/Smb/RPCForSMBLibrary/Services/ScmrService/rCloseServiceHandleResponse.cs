using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rCloseServiceHandle   Response (opnum 0)
/// </summary>
public class rCloseServiceHandleResponse
{
    public LPSC_RPC_HANDLE hSCObject;

    public rCloseServiceHandleResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        hSCObject = new LPSC_RPC_HANDLE();
        parser.ReadStructure(hSCObject);
        parser.EndStructure();
    }
}