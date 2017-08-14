using Microsoft.Diagnostics.Runtime.Interop;
using Microsoft.Diagnostics.Runtime.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace Microsoft.Diagnostics.Runtime.Tests
{
    [TestClass]
    public class PEImageTests
    {
        private readonly string Clr32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Microsoft.NET\Framework\v4.0.30319\clr.dll");
        private readonly string Clr64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Microsoft.NET\Framework64\v4.0.30319\clr.dll");
        private readonly string _mscorlib = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll");

        private Lazy<byte[]> _clr32Bytes, _clr64Bytes;

        [TestInitialize]
        public void SetUp()
        {
            _clr32Bytes = new Lazy<byte[]>(() => ReadAllBytes(Clr32));
            _clr64Bytes = new Lazy<byte[]>(() => ReadAllBytes(Clr64));
        }

        private byte[] ReadAllBytes(string file)
        {
            using (var fs = File.OpenRead(file))
            {
                byte[] bytes = new byte[fs.Length];
                if (fs.Read(bytes, 0, (int)fs.Length) != fs.Length)
                    throw new IOException();

                return bytes;
            }
        }


        [TestMethod]
        public void PEImage_Corhdr()
        {
            using (var fs = File.OpenRead(_mscorlib))
            {
                PEImage image = new PEImage(fs, false);
                Assert.IsTrue(image.IsValid);
                Assert.AreNotEqual(0, image.IndexFileSize);
                Assert.AreNotEqual(0, image.IndexTimeStamp);

                Assert.IsTrue(image.IsManaged);

                CorHeader header = image.CorHeader;
                Assert.IsNotNull(header);
            }
        }

        [TestMethod]
        public void PEImage_BasicProperties()
        {
            PEImage clr64 = GetPEImage64();
            Assert.IsTrue(clr64.IsPE64);
            Assert.IsFalse(clr64.IsManaged);

            PEImage clr32 = GetPEImage32();
            Assert.IsFalse(clr32.IsPE64);
            Assert.IsFalse(clr32.IsManaged);
        }

        [TestMethod]
        public void PEImage_Negative()
        {
            // PEImage should not throw exceptions when memory is not available

            PEImage image = GetPEImage32(maxLength: 0);
            Assert.IsFalse(image.IsValid);

            // Undefined results, but shouldn't throw
            bool tmp = image.IsPE64;
            tmp = image.IsManaged;

            Assert.AreEqual(0, image.IndexFileSize);
            Assert.AreEqual(0, image.IndexTimeStamp);

            Assert.IsNull(image.Header);
            Assert.IsNull(image.OptionalHeader);
            Assert.IsNull(image.DefaultPdb);
            Assert.IsNull(image.CorHeader);

            Assert.AreEqual(0, image.Sections.Count);
            Assert.AreEqual(0, image.Pdbs.Count);
        }

        [TestMethod]
        public void PEImage_Header()
        {
            TestHeader(GetPEImage32(maxLength: 512), IMAGE_FILE_MACHINE.I386);
            TestHeader(GetPEImage64(maxLength: 512), IMAGE_FILE_MACHINE.AMD64);
        }

        private static void TestHeader(PEImage clr, IMAGE_FILE_MACHINE machine)
        {
            ImageFileHeader header = clr.Header;
            Assert.IsTrue(clr.IsValid);
            Assert.AreEqual(machine, header.Machine);
            Assert.AreNotEqual(0, header.SizeOfOptionalHeader);
            Assert.IsTrue((header.Characteristics & IMAGE_FILE.DLL) == IMAGE_FILE.DLL);
            Assert.IsTrue((header.Characteristics & IMAGE_FILE.EXECUTABLE_IMAGE) == IMAGE_FILE.EXECUTABLE_IMAGE);
        }

        [TestMethod]
        public void PEImage_Sections()
        {
            TestSections(GetPEImage32());
            TestSections(GetPEImage64());
        }

        private static void TestSections(PEImage clr)
        {
            Assert.IsTrue(clr.IsValid);

            ImageFileHeader header = clr.Header;
            Assert.AreEqual(header.NumberOfSections, clr.Sections.Count);
            Assert.AreEqual(1, clr.Sections.Count(c => c.Name == ".data"));
            Assert.AreEqual(1, clr.Sections.Count(c => c.Name == ".text"));
        }

        private PEImage GetPEImage32(long maxLength = long.MaxValue, bool seekable = true)
        {
            return GetPEImage32(out LimitedStream stream, maxLength);
        }
        private PEImage GetPEImage64(long maxLength = long.MaxValue, bool seekable = true)
        {
            return GetPEImage64(out LimitedStream stream, maxLength);
        }

        private PEImage GetPEImage32(out LimitedStream stream, long maxLength = long.MaxValue)
        {
            byte[] bytes = _clr32Bytes.Value;
            stream = new LimitedStream(bytes, maxLength == long.MaxValue ? bytes.LongLength : maxLength);
            return new PEImage(stream, false);
        }
        private PEImage GetPEImage64(out LimitedStream stream, long maxLength = long.MaxValue)
        {
            byte[] bytes = _clr64Bytes.Value;
            stream = new LimitedStream(bytes, maxLength == long.MaxValue ? bytes.LongLength : maxLength);
            return new PEImage(stream, false);
        }
    }


    class LimitedStream : Stream
    {
        private long _position, _length;
        private byte[] _bytes;

        public LimitedStream(byte[] bytes, long maxLength)
        {
            _length = maxLength;
            _bytes = bytes;
        }

        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => false;

        public override long Length => throw new InvalidOperationException();

        public override long Position { get => _position; set => throw new InvalidOperationException(); }

        public override void Flush()
        {
            throw new InvalidOperationException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = Math.Min((int)(_length - _position), count);
            if (read <= 0)
                return 0;

            Buffer.BlockCopy(_bytes, (int)_position, buffer, offset, read);
            _position += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (origin != SeekOrigin.Begin)
                throw new NotImplementedException();
            
            _position = offset;
            return offset;
        }

        public override void SetLength(long value)
        {
            throw new InvalidOperationException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new InvalidOperationException();
        }
    }
}
