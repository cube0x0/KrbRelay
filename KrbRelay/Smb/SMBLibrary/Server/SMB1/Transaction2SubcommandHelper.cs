/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class Transaction2SubcommandHelper
    {
        internal static Transaction2FindFirst2Response GetSubcommandResponse(SMB1Header header, uint maxDataCount, Transaction2FindFirst2Request subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            string fileNamePattern = subcommand.FileName;
            if (!fileNamePattern.StartsWith(@"\"))
            {
                fileNamePattern = @"\" + fileNamePattern;
            }

            List<QueryDirectoryFileInformation> entries;
            FileInformationClass informationClass;
            try
            {
                informationClass = FindInformationHelper.ToFileInformationClass(subcommand.InformationLevel);
            }
            catch (UnsupportedInformationLevelException)
            {
                state.LogToServer(Severity.Verbose, "FindFirst2: Unsupported information level: {0}.", subcommand.InformationLevel);
                header.Status = NTStatus.STATUS_OS2_INVALID_LEVEL;
                return null;
            }

            NTStatus searchStatus = SMB1FileStoreHelper.QueryDirectory(out entries, share.FileStore, fileNamePattern, informationClass, session.SecurityContext);
            if (searchStatus != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "FindFirst2: Searched for '{0}{1}', NTStatus: {2}", share.Name, fileNamePattern, searchStatus.ToString());
                header.Status = searchStatus;
                return null;
            }
            // We ignore SearchAttributes
            state.LogToServer(Severity.Information, "FindFirst2: Searched for '{0}{1}', found {2} matching entries", share.Name, fileNamePattern, entries.Count);

            // [MS-CIFS] If no matching entries are found, the server SHOULD fail the request with STATUS_NO_SUCH_FILE.
            if (entries.Count == 0)
            {
                header.Status = NTStatus.STATUS_NO_SUCH_FILE;
                return null;
            }

            bool returnResumeKeys = (subcommand.Flags & FindFlags.SMB_FIND_RETURN_RESUME_KEYS) > 0;
            int entriesToReturn = Math.Min(subcommand.SearchCount, entries.Count);
            List<QueryDirectoryFileInformation> segment = entries.GetRange(0, entriesToReturn);
            int maxLength = (int)maxDataCount;
            FindInformationList findInformationList;
            try
            {
                findInformationList = FindInformationHelper.ToFindInformationList(segment, header.UnicodeFlag, maxLength);
            }
            catch (UnsupportedInformationLevelException)
            {
                state.LogToServer(Severity.Verbose, "FindFirst2: Unsupported information level: {0}.", subcommand.InformationLevel);
                header.Status = NTStatus.STATUS_OS2_INVALID_LEVEL;
                return null;
            }
            int returnCount = findInformationList.Count;
            Transaction2FindFirst2Response response = new Transaction2FindFirst2Response();
            response.SetFindInformationList(findInformationList, header.UnicodeFlag);
            response.EndOfSearch = (returnCount == entries.Count);
            // If [..] the search fit within a single response and SMB_FIND_CLOSE_AT_EOS is set in the Flags field,
            // or if SMB_FIND_CLOSE_AFTER_REQUEST is set in the request,
            // the server SHOULD return a SID field value of zero.
            // This indicates that the search has been closed and is no longer active on the server.
            if ((response.EndOfSearch && subcommand.CloseAtEndOfSearch) || subcommand.CloseAfterRequest)
            {
                response.SID = 0;
            }
            else
            {
                ushort? searchHandle = session.AddOpenSearch(entries, returnCount);
                if (!searchHandle.HasValue)
                {
                    header.Status = NTStatus.STATUS_OS2_NO_MORE_SIDS;
                    return null;
                }
                response.SID = searchHandle.Value;
            }
            return response;
        }

        internal static Transaction2FindNext2Response GetSubcommandResponse(SMB1Header header, uint maxDataCount, Transaction2FindNext2Request subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenSearch openSearch = session.GetOpenSearch(subcommand.SID);
            if (openSearch == null)
            {
                state.LogToServer(Severity.Verbose, "FindNext2 failed. Invalid SID.");
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return null;
            }

            bool returnResumeKeys = (subcommand.Flags & FindFlags.SMB_FIND_RETURN_RESUME_KEYS) > 0;
            int maxLength = (int)maxDataCount;
            int maxCount = Math.Min(openSearch.Entries.Count - openSearch.EnumerationLocation, subcommand.SearchCount);
            List<QueryDirectoryFileInformation> segment = openSearch.Entries.GetRange(openSearch.EnumerationLocation, maxCount);
            FindInformationList findInformationList;
            try
            {
                findInformationList = FindInformationHelper.ToFindInformationList(segment, header.UnicodeFlag, maxLength);
            }
            catch (UnsupportedInformationLevelException)
            {
                state.LogToServer(Severity.Verbose, "FindNext2: Unsupported information level: {0}.", subcommand.InformationLevel);
                header.Status = NTStatus.STATUS_OS2_INVALID_LEVEL;
                return null;
            }
            int returnCount = findInformationList.Count;
            Transaction2FindNext2Response response = new Transaction2FindNext2Response();
            response.SetFindInformationList(findInformationList, header.UnicodeFlag);
            openSearch.EnumerationLocation += returnCount;
            response.EndOfSearch = (openSearch.EnumerationLocation == openSearch.Entries.Count);
            if (response.EndOfSearch)
            {
                session.RemoveOpenSearch(subcommand.SID);
            }
            return response;
        }

        internal static Transaction2QueryFSInformationResponse GetSubcommandResponse(SMB1Header header, uint maxDataCount, Transaction2QueryFSInformationRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, @"\"))
                {
                    state.LogToServer(Severity.Verbose, "QueryFileSystemInformation on '{0}' failed. User '{1}' was denied access.", share.Name, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return null;
                }
            }

            Transaction2QueryFSInformationResponse response = new Transaction2QueryFSInformationResponse();
            if (subcommand.IsPassthroughInformationLevel)
            {
                FileSystemInformation fileSystemInfo;
                NTStatus status = share.FileStore.GetFileSystemInformation(out fileSystemInfo, subcommand.FileSystemInformationClass);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: {2}", share.Name, subcommand.FileSystemInformationClass, status);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "GetFileSystemInformation on '{0}' succeeded. Information class: {1}", share.Name, subcommand.FileSystemInformationClass);
                response.SetFileSystemInformation(fileSystemInfo);
            }
            else
            {
                QueryFSInformation queryFSInformation;
                NTStatus status = SMB1FileStoreHelper.GetFileSystemInformation(out queryFSInformation, share.FileStore, subcommand.QueryFSInformationLevel);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetFileSystemInformation on '{0}' failed. Information level: {1}, NTStatus: {2}", share.Name, subcommand.QueryFSInformationLevel, status);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "GetFileSystemInformation on '{0}' succeeded. Information level: {1}", share.Name, subcommand.QueryFSInformationLevel);
                response.SetQueryFSInformation(queryFSInformation, header.UnicodeFlag);
            }

            if (response.InformationBytes.Length > maxDataCount)
            {
                header.Status = NTStatus.STATUS_BUFFER_OVERFLOW;
                response.InformationBytes = ByteReader.ReadBytes(response.InformationBytes, 0, (int)maxDataCount);
            }
            return response;
        }

        internal static Transaction2SetFSInformationResponse GetSubcommandResponse(SMB1Header header, Transaction2SetFSInformationRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, @"\"))
                {
                    state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. User '{1}' was denied access.", share.Name, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return null;
                }
            }

            if (!subcommand.IsPassthroughInformationLevel)
            {
                state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. Not a pass-through information level.", share.Name);
                header.Status = NTStatus.STATUS_NOT_SUPPORTED;
                return null;
            }

            FileSystemInformation fileSystemInfo;
            try
            {
                fileSystemInfo = FileSystemInformation.GetFileSystemInformation(subcommand.InformationBytes, 0, subcommand.FileSystemInformationClass);
            }
            catch (UnsupportedInformationLevelException)
            {
                state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: STATUS_OS2_INVALID_LEVEL.", share.Name, subcommand.FileSystemInformationClass);
                header.Status = NTStatus.STATUS_OS2_INVALID_LEVEL;
                return null;
            }
            catch (Exception)
            {
                state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: STATUS_INVALID_PARAMETER.", share.Name, subcommand.FileSystemInformationClass);
                header.Status = NTStatus.STATUS_INVALID_PARAMETER;
                return null;
            }

            NTStatus status = share.FileStore.SetFileSystemInformation(fileSystemInfo);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: {2}.", share.Name, subcommand.FileSystemInformationClass, status);
                header.Status = status;
                return null;
            }

            state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' succeeded. Information class: {1}.", share.Name, subcommand.FileSystemInformationClass);
            return new Transaction2SetFSInformationResponse();
        }

        internal static Transaction2QueryPathInformationResponse GetSubcommandResponse(SMB1Header header, uint maxDataCount, Transaction2QueryPathInformationRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            string path = subcommand.FileName;
            if (!path.StartsWith(@"\"))
            {
                path = @"\" + path;
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, path))
                {
                    state.LogToServer(Severity.Verbose, "QueryPathInformation on '{0}{1}' failed. User '{2}' was denied access.", share.Name, path, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return null;
                }
            }

            Transaction2QueryPathInformationResponse response = new Transaction2QueryPathInformationResponse();
            if (subcommand.IsPassthroughInformationLevel && subcommand.FileInformationClass != FileInformationClass.FileAllInformation)
            {
                FileInformation fileInfo;
                NTStatus status = SMB1FileStoreHelper.GetFileInformation(out fileInfo, share.FileStore, path, subcommand.FileInformationClass, session.SecurityContext);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: {3}", share.Name, path, subcommand.FileInformationClass, status);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "GetFileInformation on '{0}{1}' succeeded. Information class: {2}", share.Name, path, subcommand.FileInformationClass);
                response.SetFileInformation(fileInfo);
            }
            else
            {
                // The FILE_ALL_INFORMATION structure described in [MS-FSCC], is NOT used by [MS-SMB]
                if (subcommand.IsPassthroughInformationLevel && subcommand.FileInformationClass == FileInformationClass.FileAllInformation)
                {
                    subcommand.QueryInformationLevel = QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO;
                }
                QueryInformation queryInformation;
                NTStatus status = SMB1FileStoreHelper.GetFileInformation(out queryInformation, share.FileStore, path, subcommand.QueryInformationLevel, session.SecurityContext);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetFileInformation on '{0}{1}' failed. Information level: {2}, NTStatus: {3}", share.Name, path, subcommand.QueryInformationLevel, status);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "GetFileInformation on '{0}{1}' succeeded. Information level: {2}", share.Name, path, subcommand.QueryInformationLevel);
                response.SetQueryInformation(queryInformation);
            }

            if (response.InformationBytes.Length > maxDataCount)
            {
                header.Status = NTStatus.STATUS_BUFFER_OVERFLOW;
                response.InformationBytes = ByteReader.ReadBytes(response.InformationBytes, 0, (int)maxDataCount);
            }
            return response;
        }

        internal static Transaction2QueryFileInformationResponse GetSubcommandResponse(SMB1Header header, uint maxDataCount, Transaction2QueryFileInformationRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(subcommand.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "QueryFileInformation failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, subcommand.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return null;
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "QueryFileInformation on '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return null;
                }
            }

            Transaction2QueryFileInformationResponse response = new Transaction2QueryFileInformationResponse();
            if (subcommand.IsPassthroughInformationLevel && subcommand.FileInformationClass != FileInformationClass.FileAllInformation)
            {
                FileInformation fileInfo;
                NTStatus status = share.FileStore.GetFileInformation(out fileInfo, openFile.Handle, subcommand.FileInformationClass);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: {3}. (FID: {4})", share.Name, openFile.Path, subcommand.FileInformationClass, status, subcommand.FID);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "GetFileInformation on '{0}{1}' succeeded. Information class: {2}. (FID: {3})", share.Name, openFile.Path, subcommand.FileInformationClass, subcommand.FID);
                response.SetFileInformation(fileInfo);
            }
            else
            {
                // The FILE_ALL_INFORMATION structure described in [MS-FSCC], is NOT used by [MS-SMB]
                if (subcommand.IsPassthroughInformationLevel && subcommand.FileInformationClass == FileInformationClass.FileAllInformation)
                {
                    subcommand.QueryInformationLevel = QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO;
                }
                QueryInformation queryInformation;
                NTStatus status = SMB1FileStoreHelper.GetFileInformation(out queryInformation, share.FileStore, openFile.Handle, subcommand.QueryInformationLevel);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetFileInformation on '{0}{1}' failed. Information level: {2}, NTStatus: {3}. (FID: {4})", share.Name, openFile.Path, subcommand.QueryInformationLevel, status, subcommand.FID);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "GetFileInformation on '{0}{1}' succeeded. Information level: {2}. (FID: {3})", share.Name, openFile.Path, subcommand.QueryInformationLevel, subcommand.FID);
                response.SetQueryInformation(queryInformation);
            }

            if (response.InformationBytes.Length > maxDataCount)
            {
                header.Status = NTStatus.STATUS_BUFFER_OVERFLOW;
                response.InformationBytes = ByteReader.ReadBytes(response.InformationBytes, 0, (int)maxDataCount);
            }
            return response;
        }

        internal static Transaction2SetFileInformationResponse GetSubcommandResponse(SMB1Header header, Transaction2SetFileInformationRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(subcommand.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "SetFileInformation failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, subcommand.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return null;
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return null;
                }
            }

            if (subcommand.IsPassthroughInformationLevel)
            {
                FileInformation fileInfo;
                try
                {
                    fileInfo = FileInformation.GetFileInformation(subcommand.InformationBytes, 0, subcommand.FileInformationClass);
                }
                catch (UnsupportedInformationLevelException)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: STATUS_OS2_INVALID_LEVEL.", share.Name, openFile.Path, subcommand.FileInformationClass);
                    header.Status = NTStatus.STATUS_OS2_INVALID_LEVEL;
                    return null;
                }
                catch (Exception)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: STATUS_INVALID_PARAMETER.", share.Name, openFile.Path, subcommand.FileInformationClass);
                    header.Status = NTStatus.STATUS_INVALID_PARAMETER;
                    return null;
                }

                NTStatus status = share.FileStore.SetFileInformation(openFile.Handle, fileInfo);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: {3}. (FID: {4})", share.Name, openFile.Path, subcommand.FileInformationClass, status, subcommand.FID);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "SetFileInformation on '{0}{1}' succeeded. Information class: {2}. (FID: {3})", share.Name, openFile.Path, subcommand.FileInformationClass, subcommand.FID);
            }
            else
            {
                SetInformation information;
                try
                {
                    information = SetInformation.GetSetInformation(subcommand.InformationBytes, subcommand.SetInformationLevel);
                }
                catch (UnsupportedInformationLevelException)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information level: {2}, NTStatus: STATUS_OS2_INVALID_LEVEL.", share.Name, openFile.Path, subcommand.SetInformationLevel);
                    header.Status = NTStatus.STATUS_OS2_INVALID_LEVEL;
                    return null;
                }
                catch (Exception)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information level: {2}, NTStatus: STATUS_INVALID_PARAMETER.", share.Name, openFile.Path, subcommand.SetInformationLevel);
                    header.Status = NTStatus.STATUS_INVALID_PARAMETER;
                    return null;
                }

                NTStatus status = SMB1FileStoreHelper.SetFileInformation(share.FileStore, openFile.Handle, information);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information level: {2}, NTStatus: {3}. (FID: {4})", share.Name, openFile.Path, subcommand.SetInformationLevel, status, subcommand.FID);
                    header.Status = status;
                    return null;
                }
                state.LogToServer(Severity.Information, "SetFileInformation on '{0}{1}' succeeded. Information level: {2}. (FID: {3})", share.Name, openFile.Path, subcommand.SetInformationLevel, subcommand.FID);
            }
            Transaction2SetFileInformationResponse response = new Transaction2SetFileInformationResponse();
            return response;
        }
    }
}