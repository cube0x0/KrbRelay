using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// OpenLocalMachine   Response (opnum 02)
/// </summary>
public class OpenLocalMachineResponse
{
    public RPC_HKEY phKey;

    public OpenLocalMachineResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        phKey = new RPC_HKEY();
        parser.ReadStructure(phKey);
    }
}