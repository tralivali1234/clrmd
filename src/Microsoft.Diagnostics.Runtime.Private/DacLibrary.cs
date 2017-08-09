// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.Diagnostics.Runtime.Private
{
    public class DacLibrary : IDisposable
    {
        #region Variables
        private IntPtr _library;
        private IXCLRDataProcess _dac;
        private HashSet<object> _release = new HashSet<object>();
        private bool _disposed = false;
        #endregion
        
        public DacLibrary(IXCLRDataProcess clrDataProcess)
        {
            _dac = clrDataProcess ?? throw new ArgumentNullException(nameof(clrDataProcess));
        }

        public DacLibrary(string dacDll, IDacDataTarget dataTarget)
        {
            _library = NativeMethods.LoadLibrary(dacDll);
            if (_library == IntPtr.Zero)
                throw new FileLoadException(dacDll);

            IntPtr addr = NativeMethods.GetProcAddress(_library, "CLRDataCreateInstance");

            NativeMethods.CreateDacInstance func = (NativeMethods.CreateDacInstance)Marshal.GetDelegateForFunctionPointer(addr, typeof(NativeMethods.CreateDacInstance));
            Guid guid = new Guid("5c552ab6-fc09-4cb3-8e36-22fa03c798b7");
            int res = func(ref guid, dataTarget, out object obj);

            if (res == 0)
                _dac = obj as IXCLRDataProcess;

            if (_dac == null)
                throw new InvalidOperationException("Failure loading DAC: CreateDacInstance failed 0x" + res.ToString("x"));
        }

        public T GetRawInterface<T>() where T : class
        {
            return (T)_dac;
        }

        public T TryGetRawInterface<T>() where T : class
        {
            return _dac as T;
        }

        /// <summary>
        /// Flush the internal dac caches.
        /// </summary>
        public void Flush()
        {
            _dac.Flush();
        }

        public int Request(uint reqCode, uint inBufferSize, byte[] inBuffer, uint outBufferSize, byte[] outBuffer)
        {
            return _dac.Request(reqCode, inBufferSize, inBuffer, outBufferSize, outBuffer);
        }

        /// <summary>
        /// Add a COM interface (IXCLR) to be explicitly released to ensure proper cleanup.
        /// </summary>
        public void AddToReleaseList(object obj)
        {
            Debug.Assert(Marshal.IsComObject(obj));
            _release.Add(obj);
        }

        #region Cleanup
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                foreach (object obj in _release)
                    Marshal.FinalReleaseComObject(obj);

                if (_dac != null)
                    Marshal.FinalReleaseComObject(_dac);

                if (_library != IntPtr.Zero)
                    NativeMethods.FreeLibrary(_library);

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~DacLibrary()
        {
            Dispose(false);
        }
        #endregion
    }
}
