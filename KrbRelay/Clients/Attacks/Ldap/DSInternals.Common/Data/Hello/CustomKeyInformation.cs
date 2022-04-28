namespace DSInternals.Common.Data
{
    using System;
    using System.IO;

    /// <summary>
    /// Represents the CUSTOM_KEY_INFORMATION structure.
    /// </summary>
    /// <see>https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf</see>
    public class CustomKeyInformation
    {
        private const byte CurrentVersion = 1;
        private const int ShortRepresentationSize = sizeof(byte) + sizeof(KeyFlags); // Version + KeyFlags
        private const int ReservedSize = 10 * sizeof(byte);

        public byte Version
        {
            get;
            private set;
        }

        public KeyFlags Flags
        {
            get;
            private set;
        }

        public VolumeType? VolumeType
        {
            get;
            private set;
        }

        /// <summary>
        /// Specifies whether the device associated with this credential supports notification.
        /// </summary>
        public bool? SupportsNotification
        {
            get;
            private set;
        }

        /// <summary>
        /// Specifies the version of the File Encryption Key (FEK).
        /// </summary>
        public byte? FekKeyVersion
        {
            get;
            private set;
        }

        /// <summary>
        /// Specifies the strength of the NGC key.
        /// </summary>
        public KeyStrength? Strength
        {
            get;
            private set;
        }

        /// <summary>
        /// Reserved for future use.
        /// </summary>
        public byte[] Reserved
        {
            get;
            private set;
        }

        /// <summary>
        /// Extended custom key information.
        /// </summary>
        public byte[] EncodedExtendedCKI
        {
            get;
            private set;
        }

        public CustomKeyInformation() : this(KeyFlags.None)
        {
        }

        public CustomKeyInformation(KeyFlags flags)
        {
            Version = CurrentVersion;
            Flags = flags;
        }

        public CustomKeyInformation(byte[] blob)
        {
            // Validate the input
            Validator.AssertNotNull(blob, nameof(blob));
            Validator.AssertMinLength(blob, ShortRepresentationSize, nameof(blob));

            using (var stream = new MemoryStream(blob, false))
            {
                // An 8-bit unsigned integer that must be set to 1:
                Version = (byte)stream.ReadByte();

                // An 8-bit unsigned integer that specifies zero or more bit-flag values.
                Flags = (KeyFlags)stream.ReadByte();

                // Note: This structure has two possible representations. In the first representation, only the Version and Flags fields are present; in this case the structure has a total size of two bytes. In the second representation, all additional fields shown below are also present; in this case, the structure's total size is variable. Differentiating between the two representations must be inferred using only the total size.
                if (stream.Position < stream.Length)
                {
                    // An 8-bit unsigned integer that specifies one of the volume types.
                    VolumeType = (VolumeType)stream.ReadByte();
                }

                if (stream.Position < stream.Length)
                {
                    // An 8-bit unsigned integer that specifies whether the device associated with this credential supports notification.
                    SupportsNotification = Convert.ToBoolean(stream.ReadByte());
                }

                if (stream.Position < stream.Length)
                {
                    // An 8-bit unsigned integer that specifies the version of the File Encryption Key (FEK). This field must be set to 1.
                    FekKeyVersion = (byte)stream.ReadByte();
                }

                if (stream.Position < stream.Length)
                {
                    // An 8-bit unsigned integer that specifies the strength of the NGC key.
                    Strength = (KeyStrength)stream.ReadByte();
                }

                if (stream.Position < stream.Length)
                {
                    // 10 bytes reserved for future use.
                    // Note: With FIDO, Azure incorrectly puts here 9 bytes instead of 10.
                    int actualReservedSize = (int)Math.Min(ReservedSize, stream.Length - stream.Position);
                    Reserved = new byte[actualReservedSize];
                    stream.Read(Reserved, 0, actualReservedSize);
                }

                if (stream.Position < stream.Length)
                {
                    // Extended custom key information.
                    EncodedExtendedCKI = stream.ReadToEnd();
                }
            }
        }

        public byte[] ToByteArray()
        {
            using (var stream = new MemoryStream())
            {
                stream.WriteByte(Version);
                stream.WriteByte((byte)Flags);

                if (VolumeType.HasValue)
                {
                    stream.WriteByte((byte)VolumeType.Value);
                }

                if (SupportsNotification.HasValue)
                {
                    stream.WriteByte(Convert.ToByte(SupportsNotification.Value));
                }

                if (FekKeyVersion.HasValue)
                {
                    stream.WriteByte(FekKeyVersion.Value);
                }

                if (Strength.HasValue)
                {
                    stream.WriteByte((byte)Strength.Value);
                }

                if (Reserved != null)
                {
                    stream.Write(Reserved, 0, Reserved.Length);
                }

                if (EncodedExtendedCKI != null)
                {
                    stream.Write(EncodedExtendedCKI, 0, EncodedExtendedCKI.Length);
                }

                return stream.ToArray();
            }
        }
    }
}