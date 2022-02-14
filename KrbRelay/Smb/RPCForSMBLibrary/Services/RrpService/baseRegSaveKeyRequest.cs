using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// BaseRegSaveKey    Request (opnum 20)
/// </summary>
public class baseRegSaveKeyRequest : IRPCRequest
{
    public RPC_HKEY hKey;
    public RPC_UNICODE_STRING lpFile;
    public RPC_SECURITY_ATTRIBUTES pSecurityAttributes;

    public baseRegSaveKeyRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hKey);
        writer.WriteStructure(lpFile);
        writer.WriteStructure(pSecurityAttributes);
        return writer.GetBytes();
    }
}