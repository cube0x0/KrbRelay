using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// ROpenSCManagerW   Request (opnum 15)
/// </summary>
public class ROpenSCManagerWRequest : IRPCRequest
{
    public string lpMachineName;
    public string lpDatabaseName;
    public SERVICE_ENUM dwDesiredAccess;

    public ROpenSCManagerWRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(null);
        writer.WriteTopLevelUnicodeStringPointer(lpDatabaseName);
        writer.WriteUInt32((uint)dwDesiredAccess);
        return writer.GetBytes();
    }
}