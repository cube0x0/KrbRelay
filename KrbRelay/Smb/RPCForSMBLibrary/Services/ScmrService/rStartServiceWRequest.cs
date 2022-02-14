using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rStartServiceW   Request (opnum 19)
/// </summary>
public class rStartServiceWRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE hService;
    public uint argc;
    public string argv;

    public rStartServiceWRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(hService);
        writer.WriteUInt32(argc);
        writer.WriteUnicodeString(argv);
        //writer.WriteEmbeddedStructureFullPointer(argv);
        return writer.GetBytes();
    }
}