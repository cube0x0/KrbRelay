using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// OpenLocalMachine   Request (opnum 02)
/// </summary>
public class OpenLocalMachineRequest : IRPCRequest
{
    public string ServerName;
    public REGSAM samDesired;

    public OpenLocalMachineRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(null);
        writer.WriteUInt32((uint)samDesired);
        return writer.GetBytes();
    }
}