using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rCloseServiceHandle   Request (opnum 0)
/// </summary>
public class rCloseServiceHandleRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hSCObject;

    public rCloseServiceHandleRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hSCObject);
        return writer.GetBytes();
    }
}