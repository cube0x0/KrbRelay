/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.2 - FileAllInformation
    /// </summary>
    public class FileAllInformation : FileInformation
    {
        public FileBasicInformation BasicInformation;
        public FileStandardInformation StandardInformation;
        public FileInternalInformation InternalInformation;
        public FileEaInformation EaInformation;
        public FileAccessInformation AccessInformation;
        public FilePositionInformation PositionInformation;
        public FileModeInformation ModeInformation;
        public FileAlignmentInformation AlignmentInformation;
        public FileNameInformation NameInformation;

        public FileAllInformation()
        {
            BasicInformation = new FileBasicInformation();
            StandardInformation = new FileStandardInformation();
            InternalInformation = new FileInternalInformation();
            EaInformation = new FileEaInformation();
            AccessInformation = new FileAccessInformation();
            PositionInformation = new FilePositionInformation();
            ModeInformation = new FileModeInformation();
            AlignmentInformation = new FileAlignmentInformation();
            NameInformation = new FileNameInformation();
        }

        public FileAllInformation(byte[] buffer, int offset)
        {
            BasicInformation = new FileBasicInformation(buffer, offset + 0);
            StandardInformation = new FileStandardInformation(buffer, offset + 40);
            InternalInformation = new FileInternalInformation(buffer, offset + 64);
            EaInformation = new FileEaInformation(buffer, offset + 72);
            AccessInformation = new FileAccessInformation(buffer, offset + 76);
            PositionInformation = new FilePositionInformation(buffer, offset + 80);
            ModeInformation = new FileModeInformation(buffer, offset + 88);
            AlignmentInformation = new FileAlignmentInformation(buffer, offset + 92);
            NameInformation = new FileNameInformation(buffer, offset + 96);
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            BasicInformation.WriteBytes(buffer, offset + 0);
            StandardInformation.WriteBytes(buffer, offset + 40);
            InternalInformation.WriteBytes(buffer, offset + 64);
            EaInformation.WriteBytes(buffer, offset + 72);
            AccessInformation.WriteBytes(buffer, offset + 76);
            PositionInformation.WriteBytes(buffer, offset + 80);
            ModeInformation.WriteBytes(buffer, offset + 88);
            AlignmentInformation.WriteBytes(buffer, offset + 92);
            NameInformation.WriteBytes(buffer, offset + 96);
        }

        public override FileInformationClass FileInformationClass
        {
            get
            {
                return FileInformationClass.FileAllInformation;
            }
        }

        public override int Length
        {
            get
            {
                return 96 + NameInformation.Length;
            }
        }
    }
}