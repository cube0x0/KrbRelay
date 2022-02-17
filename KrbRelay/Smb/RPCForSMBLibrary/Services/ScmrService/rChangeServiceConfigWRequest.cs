using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// rChangeServiceConfigW   Request (opnum 11)
/// </summary>
public class rChangeServiceConfigWRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE lpScHandle;
    public uint dwServiceType;
    public SERIVCE_STARTUP dwStartType;
    public uint dwErrorControl;
    public string lpBinaryPathName;
    public string lpLoadOrderGroup;
    public uint lpdwTagId;
    public string lpDependencies;
    public uint dwDependSize;
    public string lpServiceStartName;
    public string lpPassword;
    public uint dwPwSize;
    public string lpDisplayName;

    public rChangeServiceConfigWRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(lpScHandle);
        writer.WriteUInt32((uint)dwServiceType);
        writer.WriteUInt32((uint)dwStartType);
        writer.WriteUInt32((uint)dwErrorControl);
        writer.WriteTopLevelUnicodeStringPointer(lpBinaryPathName);
        writer.WriteTopLevelUnicodeStringPointer(lpLoadOrderGroup);
        writer.WriteUInt32((uint)lpdwTagId);
        writer.WriteTopLevelUnicodeStringPointer(lpDependencies);
        writer.WriteUInt32((uint)dwDependSize);
        writer.WriteTopLevelUnicodeStringPointer(lpServiceStartName);
        writer.WriteTopLevelUnicodeStringPointer(lpPassword);
        writer.WriteUInt32((uint)dwPwSize);
        writer.WriteTopLevelUnicodeStringPointer(lpDisplayName);

        return writer.GetBytes();
    }
}