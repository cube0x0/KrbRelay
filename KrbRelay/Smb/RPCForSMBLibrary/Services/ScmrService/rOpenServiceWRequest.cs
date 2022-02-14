using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rOpenServiceW   Request (opnum 16)
/// </summary>
public class rOpenServiceWRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hSCManager;
    public string lpServiceName;
    public SERVICE_ENUM dwDesiredAccess;

    public rOpenServiceWRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hSCManager);
        writer.WriteUnicodeString(lpServiceName);
        writer.WriteUInt32((uint)dwDesiredAccess);
        return writer.GetBytes();
    }
}