using Microsoft.Diagnostics.Runtime.Interop;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

#pragma warning disable 1591

namespace Microsoft.Diagnostics.Runtime.Utilities
{
    public unsafe class PEImage
    {
        private const ushort ExpectedDosHeaderMagic = 0x5A4D;   // MZ
        private const int PESignatureOffsetLocation = 0x3C;
        private const uint ExpectedPESignature = 0x00004550;    // PE00
        private const int ImageDataDirectoryCount = 15;
        private const int ComDataDirectory = 14;
        private const int DebugDataDirectory = 6;

        private bool _virt;
        private Stream _stream;
        private byte[] _buffer = new byte[260];
        private int _offset = 0;
        private int _peHeaderOffset;

        private Lazy<ImageFileHeader> _imageFileHeader;
        private Lazy<ImageOptionalHeader> _imageOptionalHeader;
        private Lazy<CorHeader> _corHeader;
        private Lazy<List<SectionHeader>> _sections;
        private Lazy<List<PdbInfo>> _pdbs;
        private Lazy<Interop.IMAGE_DATA_DIRECTORY[]> _directories;

        public PEImage(Stream stream, bool virt)
        {
            if (!stream.CanSeek)
                throw new ArgumentException($"{nameof(stream)} is not seekable.");

            _virt = virt;
            _stream = stream;

            ushort? dosHeaderMagic = Read<ushort>(0);
            if (dosHeaderMagic != ExpectedDosHeaderMagic)
            {
                IsValid = false;
            }
            else
            {
                _peHeaderOffset = Read<int>(PESignatureOffsetLocation) ?? 0;
                uint? peSignature = null;
                
                if  (_peHeaderOffset != 0) 
                    peSignature = Read<uint>(_peHeaderOffset);

                IsValid = peSignature.HasValue && peSignature.Value == ExpectedPESignature;
            }

            _imageFileHeader = new Lazy<ImageFileHeader>(ReadImageFileHeader);
            _imageOptionalHeader = new Lazy<ImageOptionalHeader>(ReadImageOptionalHeader);
            _corHeader = new Lazy<CorHeader>(ReadCorHeader);
            _directories = new Lazy<Interop.IMAGE_DATA_DIRECTORY[]>(ReadDataDirectories);
            _sections = new Lazy<List<SectionHeader>>(ReadSections);
            _pdbs = new Lazy<List<PdbInfo>>(ReadPdbs);
        }

        public bool IsValid { get; private set; }
        public bool IsPE64 => OptionalHeader != null ? OptionalHeader.Magic != 0x010b : false;
        public bool IsManaged => GetDirectory(14).VirtualAddress != 0;
        public int IndexTimeStamp => (int)(Header?.TimeDateStamp ?? 0);

        public int IndexFileSize => (int)(OptionalHeader?.SizeOfImage ?? 0);

        public CorHeader CorHeader => _corHeader.Value;
        public ImageFileHeader Header => _imageFileHeader.Value;
        public ImageOptionalHeader OptionalHeader => _imageOptionalHeader.Value;
        public ReadOnlyCollection<SectionHeader> Sections => _sections.Value.AsReadOnly();
        public ReadOnlyCollection<PdbInfo> Pdbs => _pdbs.Value.AsReadOnly();
        public PdbInfo DefaultPdb => Pdbs.LastOrDefault();

        public int RvaToOffset(int rva)
        {
            if (_virt)
                return rva;

            List<SectionHeader> sections = _sections.Value;
            for (int i = 0; i < sections.Count; i++)
                if (sections[i].VirtualAddress <= rva && rva < sections[i].VirtualAddress + sections[i].VirtualSize)
                    return (int)sections[i].PointerToRawData + (rva - (int)sections[i].VirtualAddress);

            return -1;
        }
        
        public int Read(IntPtr dest, int rva, int bytesRequested)
        {
            byte[] buffer = _buffer;
            EnsureSize(ref buffer, bytesRequested);

            int offset = RvaToOffset(rva);
            if (offset == -1)
                return 0;

            SeekTo(offset);
            int read = _stream.Read(buffer, 0, bytesRequested);
            if (read > 0)
                Marshal.Copy(buffer, 0, dest, read);

            return read;
        }

        public int Read(byte[] dest, int rva, int bytesRequested)
        {
            int offset = RvaToOffset(rva);
            if (offset == -1)
                return 0;

            SeekTo(offset);
            int read = _stream.Read(dest, 0, bytesRequested);
            return read;
        }

        private Interop.IMAGE_DATA_DIRECTORY GetDirectory(int index) => _directories.Value[index];
        private int HeaderOffset => _peHeaderOffset + sizeof(uint);
        private int OptionalHeaderOffset => HeaderOffset + sizeof(IMAGE_FILE_HEADER);
        private int SpecificHeaderOffset => OptionalHeaderOffset + sizeof(IMAGE_OPTIONAL_HEADER_AGNOSTIC);
        private int DataDirectoryOffset => SpecificHeaderOffset + (IsPE64 ? 5 * 8 : 6 * 4);
        private int ImageDataDirectoryOffset => DataDirectoryOffset + ImageDataDirectoryCount * sizeof(Interop.IMAGE_DATA_DIRECTORY);
        

        private List<SectionHeader> ReadSections()
        {
            List<SectionHeader> sections = new List<SectionHeader>();
            if (!IsValid)
                return sections;

            ImageFileHeader header = Header;
            if (header == null)
                return sections;

            SeekTo(ImageDataDirectoryOffset);

            // Sanity check, there's a null row at the end of the data directory table
            ulong? zero = Read<ulong>();
            if (zero != 0)
                return sections;

            for (int i = 0; i < header.NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER? sectionHdr = Read<IMAGE_SECTION_HEADER>();
                if (sectionHdr.HasValue)
                    sections.Add(new SectionHeader(sectionHdr.Value));
            }

            return sections;
        }

        private List<PdbInfo> ReadPdbs()
        {
            int offs = _offset;
            List<PdbInfo> result = new List<PdbInfo>();

            var debugData = GetDirectory(DebugDataDirectory);
            if (debugData.VirtualAddress != 0 && debugData.Size != 0)
            {
                if ((debugData.Size % sizeof(IMAGE_DEBUG_DIRECTORY)) != 0)
                    return result;
                
                int offset = RvaToOffset((int)debugData.VirtualAddress);
                if (offset == -1)
                    return result;

                int count = (int)debugData.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
                List<Tuple<int,int>> entries = new List<Tuple<int, int>>(count);

                SeekTo(offset);
                for (int i = 0; i < count; i++)
                {
                    IMAGE_DEBUG_DIRECTORY? entryRead = Read<IMAGE_DEBUG_DIRECTORY>();
                    if (entryRead.HasValue)
                    {
                        IMAGE_DEBUG_DIRECTORY tmp = entryRead.Value;
                        if (tmp.Type == IMAGE_DEBUG_TYPE.CODEVIEW && tmp.SizeOfData >= sizeof(CV_INFO_PDB70))
                            entries.Add(Tuple.Create(_virt ? tmp.AddressOfRawData : tmp.PointerToRawData, tmp.SizeOfData));
                    }
                }

                foreach (Tuple<int,int> tmp in entries.OrderBy(e => e.Item1))
                {
                    int ptr = tmp.Item1;
                    int size = tmp.Item2;

                    int? cvSig = Read<int>(ptr);
                    if (cvSig.HasValue && cvSig.Value == CV_INFO_PDB70.PDB70CvSignature)
                    {
                        Guid guid = Read<Guid>() ?? default(Guid);
                        int age = Read<int>() ?? -1;

                        // sizeof(sig) + sizeof(guid) + sizeof(age) - [null char] = 0x18 - 1
                        int nameLen = size - 0x18 - 1;
                        string filename = ReadString(nameLen);


                        PdbInfo pdb = new PdbInfo(filename, guid, age);
                        result.Add(pdb);
                    }
                }
            }

            return result;
        }

        private string ReadString(int len)
        {
            return ReadString(_offset, len);
        }

        private string ReadString(int offset, int len)
        {
            if (len > 4096)
                len = 4096;

            SeekTo(offset);

            byte[] buffer = _buffer;
            EnsureSize(ref buffer, len);

            if (_stream.Read(_buffer, 0, len) != len)
                return null;

            return Encoding.ASCII.GetString(_buffer, 0, len);
        }

        private T? Read<T>() where T : struct
        {
            return Read<T>(_offset);
        }

        private T? Read<T>(int offset) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));

            SeekTo(offset);
            EnsureSize(ref _buffer, size);

            if (_stream.Read(_buffer, 0, size) != size)
                return null;

            _offset = offset + size;
            fixed (byte* buffer = _buffer)
                return (T)Marshal.PtrToStructure(new IntPtr(buffer), typeof(T));
        }

        private static void EnsureSize(ref byte[] readBuffer, int size)
        {
            if (readBuffer == null || readBuffer.Length < size)
                readBuffer = new byte[size];
        }

        private void SeekTo(int offset)
        {
            if (offset != _offset)
            {
                _stream.Seek(offset, SeekOrigin.Begin);
                _offset = offset;
            }
        }
        
        private ImageFileHeader ReadImageFileHeader()
        {
            IMAGE_FILE_HEADER? header = Read<IMAGE_FILE_HEADER>(HeaderOffset);
            return header.HasValue ? new ImageFileHeader(header.Value) : null;
        }
        
        private Interop.IMAGE_DATA_DIRECTORY[] ReadDataDirectories()
        {
            SeekTo(DataDirectoryOffset);
            Interop.IMAGE_DATA_DIRECTORY[] directories = new Interop.IMAGE_DATA_DIRECTORY[ImageDataDirectoryCount];
            for (int i = 0; i < directories.Length; i++)
                directories[i] = Read<Interop.IMAGE_DATA_DIRECTORY>() ?? default(Interop.IMAGE_DATA_DIRECTORY);

            return directories;
        }

        private ImageOptionalHeader ReadImageOptionalHeader()
        {
            if (!IsValid)
                return null;

            IMAGE_OPTIONAL_HEADER_AGNOSTIC? optional = Read<IMAGE_OPTIONAL_HEADER_AGNOSTIC>(OptionalHeaderOffset);
            if (!optional.HasValue)
                return null;

            bool is32Bit = optional.Value.Magic == 0x010b;
            Lazy<IMAGE_OPTIONAL_HEADER_SPECIFIC> specific = new Lazy<IMAGE_OPTIONAL_HEADER_SPECIFIC>(() =>
            {
                SeekTo(SpecificHeaderOffset);
                return new IMAGE_OPTIONAL_HEADER_SPECIFIC()
                {
                    SizeOfStackReserve = (is32Bit ? Read<uint>() : Read<ulong>()) ?? 0,
                    SizeOfStackCommit = (is32Bit ? Read<uint>() : Read<ulong>()) ?? 0,
                    SizeOfHeapReserve = (is32Bit ? Read<uint>() : Read<ulong>()) ?? 0,
                    SizeOfHeapCommit = (is32Bit ? Read<uint>() : Read<ulong>()) ?? 0,
                    LoaderFlags = (Read<uint>()) ?? 0,
                    NumberOfRvaAndSizes = (Read<uint>()) ?? 0
                };
            });
            
            return new ImageOptionalHeader(optional.Value, specific, _directories, is32Bit);
        }

        private CorHeader ReadCorHeader()
        {
            var clrDataDirectory = GetDirectory(ComDataDirectory);
            
            int offset = RvaToOffset((int)clrDataDirectory.VirtualAddress);
            if (offset == -1)
                return null;

            IMAGE_COR20_HEADER? corHdr = Read<IMAGE_COR20_HEADER>(offset);
            return corHdr.HasValue ? new CorHeader(corHdr.Value) : null;
        }
    }

    public class SectionHeader
    {
        public string Name { get; private set; }
        public uint VirtualSize { get; private set; }
        public uint VirtualAddress { get; private set; }
        public uint SizeOfRawData { get; private set; }
        public uint PointerToRawData { get; private set; }
        public uint PointerToRelocations { get; private set; }
        public uint PointerToLineNumbers { get; private set; }
        public ushort NumberOfRelocations { get; private set; }
        public ushort NumberOfLineNumbers { get; private set; }
        public IMAGE_SCN Characteristics { get; private set; }

        internal SectionHeader(IMAGE_SECTION_HEADER section)
        {
            Name = section.Name;
            VirtualSize = section.VirtualSize;
            VirtualAddress = section.VirtualAddress;
            SizeOfRawData = section.SizeOfRawData;
            PointerToRawData = section.PointerToRawData;
            PointerToRelocations = section.PointerToRelocations;
            PointerToLineNumbers = section.PointerToLinenumbers;
            NumberOfRelocations = section.NumberOfRelocations;
            NumberOfLineNumbers = section.NumberOfLinenumbers;
            Characteristics = (IMAGE_SCN)section.Characteristics;
        }

        public override string ToString() => Name;
    }

    public class CorHeader
    {
        private IMAGE_COR20_HEADER _header;

        internal CorHeader(IMAGE_COR20_HEADER header)
        {
            _header = header;
        }

        public COMIMAGE_FLAGS Flags => (COMIMAGE_FLAGS)_header.Flags;
        public UInt16 MajorRuntimeVersion => _header.MajorRuntimeVersion;
        public UInt16 MinorRuntimeVersion => _header.MinorRuntimeVersion;

        // Symbol table and startup information
        public Interop.IMAGE_DATA_DIRECTORY Metadata => _header.MetaData;

        public uint NativeEntryPoint => (Flags & COMIMAGE_FLAGS.NATIVE_ENTRYPOINT) == COMIMAGE_FLAGS.NATIVE_ENTRYPOINT ? _header.EntryPoint._RVA : throw new InvalidOperationException();
        public uint ManagedEntryPoint => (Flags & COMIMAGE_FLAGS.NATIVE_ENTRYPOINT) != COMIMAGE_FLAGS.NATIVE_ENTRYPOINT ? _header.EntryPoint._token : throw new InvalidOperationException();

        /// <summary>
        /// This is the blob of managed resources. Fetched using code:AssemblyNative.GetResource and
        /// code:PEFile.GetResource and accessible from managed code from
        /// System.Assembly.GetManifestResourceStream.  The meta data has a table that maps names to offsets into
        /// this blob, so logically the blob is a set of resources.
        /// </summary>
        public Interop.IMAGE_DATA_DIRECTORY Resources => _header.Resources;

        /// <summary>
        /// IL assemblies can be signed with a public-private key to validate who created it.  The signature goes
        /// here if this feature is used.
        /// </summary>
        public Interop.IMAGE_DATA_DIRECTORY StrongNameSignature => _header.StrongNameSignature;
        
        /// <summary>
        /// Used for managed codeethat has unmanaged code inside of it (or exports methods as unmanaged entry points) .
        /// </summary>
        public Interop.IMAGE_DATA_DIRECTORY VTableFixups => _header.VTableFixups;
        public Interop.IMAGE_DATA_DIRECTORY ExportAddressTableJumps => _header.ExportAddressTableJumps;

        /// <summary>
        /// This is null for ordinary IL images.  NGEN images it points at a CORCOMPILE_HEADER structure.
        /// </summary>
        public Interop.IMAGE_DATA_DIRECTORY ManagedNativeHeader => _header.ManagedNativeHeader;
    }

    public class ImageFileHeader
    {
        private IMAGE_FILE_HEADER _header;

        internal ImageFileHeader(IMAGE_FILE_HEADER header)
        {
            _header = header;
        }

        /// <summary>
        /// The architecture type of the computer. An image file can only be run on the specified computer or a system that emulates the specified computer. 
        /// </summary>
        public IMAGE_FILE_MACHINE Machine => (IMAGE_FILE_MACHINE)_header.Machine;

        /// <summary>
        /// The number of sections. This indicates the size of the section table, which immediately follows the headers. Note that the Windows loader limits the number of sections to 96.
        /// </summary>
        public ushort NumberOfSections => _header.NumberOfSections;

        /// <summary>
        /// The offset of the symbol table, in bytes, or zero if no COFF symbol table exists.
        /// </summary>
        public uint PointerToSymbolTable => _header.PointerToSymbolTable;

        /// <summary>
        /// The number of symbols in the symbol table.
        /// </summary>
        public uint NumberOfSymbols => _header.NumberOfSymbols;

        /// <summary>
        /// The low 32 bits of the time stamp of the image. This represents the date and time the image was created by the linker. The value is represented in the number of seconds elapsed since midnight (00:00:00), January 1, 1970, Universal Coordinated Time, according to the system clock.
        /// </summary>
        public uint TimeDateStamp => _header.TimeDateStamp;

        /// <summary>
        /// The size of the optional header, in bytes. This value should be 0 for object files.
        /// </summary>
        public ushort SizeOfOptionalHeader => _header.SizeOfOptionalHeader;

        /// <summary>
        /// The characteristics of the image
        /// </summary>
        public IMAGE_FILE Characteristics => (IMAGE_FILE)_header.Characteristics;
    }

    public class ImageOptionalHeader
    {
        private bool _32bit;
        private IMAGE_OPTIONAL_HEADER_AGNOSTIC _optional;
        private Lazy<IMAGE_OPTIONAL_HEADER_SPECIFIC> _specific;
        private Lazy<Interop.IMAGE_DATA_DIRECTORY[]> _directories;

        private IMAGE_OPTIONAL_HEADER_SPECIFIC OptionalSpecific => _specific.Value;

        internal ImageOptionalHeader(IMAGE_OPTIONAL_HEADER_AGNOSTIC optional, Lazy<IMAGE_OPTIONAL_HEADER_SPECIFIC> specific, Lazy<Interop.IMAGE_DATA_DIRECTORY[]> directories, bool is32bit)
        {
            _optional = optional;
            _specific = specific;
            _32bit = is32bit;
            _directories = directories;
        }

        public ushort Magic => _optional.Magic;
        public byte MajorLinkerVersion => _optional.MajorLinkerVersion;
        public byte MinorLinkerVersion => _optional.MinorLinkerVersion;
        public uint SizeOfCode => _optional.SizeOfCode;
        public uint SizeOfInitializedData => _optional.SizeOfInitializedData;
        public uint SizeOfUninitializedData => _optional.SizeOfUninitializedData;
        public uint AddressOfEntryPoint => _optional.AddressOfEntryPoint;
        public uint BaseOfCode => _optional.BaseOfCode;
        public uint BaseOfData => _32bit ? _optional.BaseOfData : throw new InvalidOperationException();
        public ulong ImageBase => _32bit ? _optional.ImageBase : _optional.ImageBase64;
        public uint SectionAlignment => _optional.SectionAlignment;
        public uint FileAlignment => _optional.FileAlignment;
        public ushort MajorOperatingSystemVersion => _optional.MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion => _optional.MinorOperatingSystemVersion;
        public ushort MajorImageVersion => _optional.MajorImageVersion;
        public ushort MinorImageVersion => _optional.MinorImageVersion;
        public ushort MajorSubsystemVersion => _optional.MajorSubsystemVersion;
        public ushort MinorSubsystemVersion => _optional.MinorSubsystemVersion;
        public uint Win32VersionValue => _optional.Win32VersionValue;
        public uint SizeOfImage => _optional.SizeOfImage;
        public uint SizeOfHeaders => _optional.SizeOfHeaders;
        public uint CheckSum => _optional.CheckSum;
        public ushort Subsystem => _optional.Subsystem;
        public ushort DllCharacteristics => _optional.DllCharacteristics;

        public ulong SizeOfStackReserve => OptionalSpecific.SizeOfStackReserve;
        public ulong SizeOfStackCommit => OptionalSpecific.SizeOfStackCommit;
        public ulong SizeOfHeapReserve => OptionalSpecific.SizeOfHeapReserve;
        public ulong SizeOfHeapCommit => OptionalSpecific.SizeOfHeapCommit;
        public uint LoaderFlags => OptionalSpecific.LoaderFlags;
        public uint NumberOfRvaAndSizes => OptionalSpecific.NumberOfRvaAndSizes;
        
        public Interop.IMAGE_DATA_DIRECTORY ExportDirectory => _directories.Value[0];
        public Interop.IMAGE_DATA_DIRECTORY ImportDirectory => _directories.Value[1];
        public Interop.IMAGE_DATA_DIRECTORY ResourceDirectory => _directories.Value[2];
        public Interop.IMAGE_DATA_DIRECTORY ExceptionDirectory => _directories.Value[3];
        public Interop.IMAGE_DATA_DIRECTORY CertificatesDirectory => _directories.Value[4];
        public Interop.IMAGE_DATA_DIRECTORY BaseRelocationDirectory => _directories.Value[5];
        public Interop.IMAGE_DATA_DIRECTORY DebugDirectory => _directories.Value[6];
        public Interop.IMAGE_DATA_DIRECTORY ArchitectureDirectory => _directories.Value[7];
        public Interop.IMAGE_DATA_DIRECTORY GlobalPointerDirectory => _directories.Value[8];
        public Interop.IMAGE_DATA_DIRECTORY ThreadStorageDirectory => _directories.Value[9];
        public Interop.IMAGE_DATA_DIRECTORY LoadConfigurationDirectory => _directories.Value[10];
        public Interop.IMAGE_DATA_DIRECTORY BoundImportDirectory => _directories.Value[11];
        public Interop.IMAGE_DATA_DIRECTORY ImportAddressTableDirectory => _directories.Value[12];
        public Interop.IMAGE_DATA_DIRECTORY DelayImportDirectory => _directories.Value[13];
        public Interop.IMAGE_DATA_DIRECTORY ComDescriptorDirectory => _directories.Value[14];
    }



    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_OPTIONAL_HEADER_AGNOSTIC
    {
        [FieldOffset(0)]
        public ushort Magic;
        [FieldOffset(2)]
        public byte MajorLinkerVersion;
        [FieldOffset(3)]
        public byte MinorLinkerVersion;
        [FieldOffset(4)]
        public UInt32 SizeOfCode;
        [FieldOffset(8)]
        public UInt32 SizeOfInitializedData;
        [FieldOffset(12)]
        public UInt32 SizeOfUninitializedData;
        [FieldOffset(16)]
        public UInt32 AddressOfEntryPoint;
        [FieldOffset(20)]
        public UInt32 BaseOfCode;
        [FieldOffset(24)]
        public UInt64 ImageBase64;
        [FieldOffset(24)]
        public UInt32 BaseOfData;
        [FieldOffset(28)]
        public UInt32 ImageBase;
        [FieldOffset(32)]
        public UInt32 SectionAlignment;
        [FieldOffset(36)]
        public UInt32 FileAlignment;
        [FieldOffset(40)]
        public ushort MajorOperatingSystemVersion;
        [FieldOffset(42)]
        public ushort MinorOperatingSystemVersion;
        [FieldOffset(44)]
        public ushort MajorImageVersion;
        [FieldOffset(46)]
        public ushort MinorImageVersion;
        [FieldOffset(48)]
        public ushort MajorSubsystemVersion;
        [FieldOffset(50)]
        public ushort MinorSubsystemVersion;
        [FieldOffset(52)]
        public UInt32 Win32VersionValue;
        [FieldOffset(56)]
        public UInt32 SizeOfImage;
        [FieldOffset(60)]
        public UInt32 SizeOfHeaders;
        [FieldOffset(64)]
        public UInt32 CheckSum;
        [FieldOffset(68)]
        public ushort Subsystem;
        [FieldOffset(70)]
        public ushort DllCharacteristics;
    }

    internal struct IMAGE_OPTIONAL_HEADER_SPECIFIC
    {
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }
}
