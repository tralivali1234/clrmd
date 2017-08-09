// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Diagnostics.Runtime.Private;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Microsoft.Diagnostics.Runtime.Desktop
{
    internal class V45Runtime : DesktopRuntimeBase
    {
        private ISOSDac _sos;

        #region Constructor
        public V45Runtime(ClrInfo info, DataTargetImpl dt, DacLibrary lib)
            : base(info, dt, lib)
        {
            if (!GetCommonMethodTables(ref _commonMTs))
                throw new ClrDiagnosticsException("Could not request common MethodTable list.", ClrDiagnosticsException.HR.DacError);

            if (!_commonMTs.Validate())
                CanWalkHeap = false;

            // Ensure the version of the dac API matches the one we expect.  (Same for both
            // v2 and v4 rtm.)
            byte[] tmp = new byte[sizeof(int)];

            if (!Request(DacRequests.VERSION, null, tmp))
                throw new ClrDiagnosticsException("Failed to request dac version.", ClrDiagnosticsException.HR.DacError);

            int v = BitConverter.ToInt32(tmp, 0);
            if (v != 9)
                throw new ClrDiagnosticsException("Unsupported dac version.", ClrDiagnosticsException.HR.DacError);
        }
        #endregion

        #region Overrides
        protected override void InitApi()
        {
            _sos = _library.GetRawInterface<ISOSDac>();
        }
        internal override DesktopVersion CLRVersion
        {
            get { return DesktopVersion.v45; }
        }

        private ISOSHandleEnum _handleEnum;
        private List<ClrHandle> _handles;

        public override IEnumerable<ClrHandle> EnumerateHandles()
        {
            if (_handles != null && _handleEnum == null)
                return _handles;

            return EnumerateHandleWorker();
        }

        internal override Dictionary<ulong, List<ulong>> GetDependentHandleMap(CancellationToken cancelToken)
        {
            Dictionary<ulong, List<ulong>> result = new Dictionary<ulong, List<ulong>>();

            if (_sos.GetHandleEnum(out object tmp) < 0)
                return result;

            ISOSHandleEnum enumerator = (ISOSHandleEnum)tmp;
            HandleData[] handles = new HandleData[32];
            uint fetched = 0;
            do
            {
                if (enumerator.Next((uint)handles.Length, handles, out fetched) < 0 || fetched <= 0)
                    break;
                
                for (int i = 0; i < fetched; i++)
                {
                    cancelToken.ThrowIfCancellationRequested();
                        
                    HandleType type = (HandleType)handles[i].Type;
                    if (type != HandleType.Dependent)
                        continue;

                    if (ReadPointer(handles[i].Handle, out ulong address))
                    {
                        if (!result.TryGetValue(address, out List<ulong> value))
                            result[address] = value = new List<ulong>();

                        value.Add(handles[i].Secondary);
                    }
                }
            } while (fetched > 0);

            return result;
        }

        private IEnumerable<ClrHandle> EnumerateHandleWorker()
        {
            // handles was fully populated already
            if (_handles != null && _handleEnum == null)
                yield break;

            // Create _handleEnum if it's not already created.
            if (_handleEnum == null)
            {
                if (_sos.GetHandleEnum(out object tmp) < 0)
                    yield break;

                _handleEnum = tmp as ISOSHandleEnum;
                if (_handleEnum == null)
                    yield break;

                _handles = new List<ClrHandle>();
            }

            // We already partially enumerated handles before, start with them.
            foreach (var handle in _handles)
                yield return handle;

            HandleData[] handles = new HandleData[8];
            uint fetched = 0;
            do
            {
                if (_handleEnum.Next((uint)handles.Length, handles, out fetched) < 0 || fetched <= 0)
                    break;

                int curr = _handles.Count;
                for (int i = 0; i < fetched; i++)
                {
                    ClrHandle handle = new ClrHandle(this, Heap, handles[i]);
                    _handles.Add(handle);

                    handle = handle.GetInteriorHandle();
                    if (handle != null)
                    {
                        _handles.Add(handle);
                        yield return handle;
                    }
                }

                for (int i = curr; i < _handles.Count; i++)
                    yield return _handles[i];
            } while (fetched > 0);

            _handleEnum = null;
        }

        internal override IEnumerable<ClrRoot> EnumerateStackReferences(ClrThread thread, bool includeDead)
        {
            if (includeDead)
                return base.EnumerateStackReferences(thread, includeDead);

            return EnumerateStackReferencesWorker(thread);
        }

        private IEnumerable<ClrRoot> EnumerateStackReferencesWorker(ClrThread thread)
        {
            ISOSStackRefEnum handleEnum = null;
            if (_sos.GetStackReferences(thread.OSThreadId, out object tmp) >= 0)
                handleEnum = tmp as ISOSStackRefEnum;

            ClrAppDomain domain = GetAppDomainByAddress(thread.AppDomain);
            if (handleEnum != null)
            {
                var heap = Heap;
                StackRefData[] refs = new StackRefData[1024];

                const int GCInteriorFlag = 1;
                const int GCPinnedFlag = 2;
                uint fetched = 0;
                do
                {
                    if (handleEnum.Next((uint)refs.Length, refs, out fetched) < 0)
                        break;

                    for (uint i = 0; i < fetched && i < refs.Length; ++i)
                    {
                        if (refs[i].Object == 0)
                            continue;

                        bool pinned = (refs[i].Flags & GCPinnedFlag) == GCPinnedFlag;
                        bool interior = (refs[i].Flags & GCInteriorFlag) == GCInteriorFlag;

                        ClrType type = null;

                        if (!interior)
                            type = heap.GetObjectType(refs[i].Object);

                        ClrStackFrame frame = thread.StackTrace.SingleOrDefault(f => f.StackPointer == refs[i].Source || (f.StackPointer == refs[i].StackPointer && f.InstructionPointer == refs[i].Source));

                        if (interior || type != null)
                            yield return new LocalVarRoot(refs[i].Address, refs[i].Object, type, domain, thread, pinned, false, interior, frame);
                    }
                } while (fetched == refs.Length);
            }
        }

        internal override ulong GetFirstThread()
        {
            IThreadStoreData threadStore = GetThreadStoreData();
            return threadStore != null ? threadStore.FirstThread : 0;
        }

        internal override IThreadData GetThread(ulong addr)
        {
            if (addr == 0)
                return null;

            if (_sos.GetThreadData(addr, out V4ThreadData data) < 0)
                return null;

            return data;
        }

        internal override IHeapDetails GetSvrHeapDetails(ulong addr)
        {
            if (_sos.GetGCHeapDetails(addr, out V4HeapDetails data) < 0)
                return null;
            return data;
        }

        internal override IHeapDetails GetWksHeapDetails()
        {
            if (_sos.GetGCHeapStaticData(out V4HeapDetails data) < 0)
                return null;
            return data;
        }

        internal override ulong[] GetServerHeapList()
        {
            ulong[] refs = new ulong[HeapCount];
            if (_sos.GetGCHeapList((uint)HeapCount, refs, out uint needed) < 0)
                return null;

            return refs;
        }

        internal override IList<ulong> GetAppDomainList(int count)
        {
            ulong[] data = new ulong[1024];
            if (_sos.GetAppDomainList((uint)data.Length, data, out uint needed) < 0)
                return null;

            List<ulong> list = new List<ulong>((int)needed);

            for (uint i = 0; i < needed; ++i)
                list.Add(data[i]);

            return list;
        }

        internal override ulong[] GetAssemblyList(ulong appDomain, int count)
        {
            int needed;
            if (count <= 0)
            {
                if (_sos.GetAssemblyList(appDomain, 0, null, out needed) < 0)
                    return new ulong[0];

                count = needed;
            }

            // We ignore the return value here since modules might be partially
            // filled even if GetAssemblyList hits an error.
            ulong[] modules = new ulong[count];
            _sos.GetAssemblyList(appDomain, modules.Length, modules, out needed);

            return modules;
        }

        internal override ulong[] GetModuleList(ulong assembly, int count)
        {
            uint needed = (uint)count;

            if (count <= 0)
            {
                if (_sos.GetAssemblyModuleList(assembly, 0, null, out needed) < 0)
                    return new ulong[0];
            }

            // We ignore the return value here since modules might be partially
            // filled even if GetAssemblyList hits an error.
            ulong[] modules = new ulong[needed];
            _sos.GetAssemblyModuleList(assembly, needed, modules, out needed);
            return modules;
        }

        internal override IAssemblyData GetAssemblyData(ulong domain, ulong assembly)
        {
            if (_sos.GetAssemblyData(domain, assembly, out LegacyAssemblyData data) < 0)
            {
                // The dac seems to have an issue where the assembly data can be filled in for a minidump.
                // If the data is partially filled in, we'll use it.
                if (data.Address != assembly)
                    return null;
            }

            return data;
        }

        internal override IAppDomainStoreData GetAppDomainStoreData()
        {
            if (_sos.GetAppDomainStoreData(out LegacyAppDomainStoreData data) < 0)
                return null;

            return data;
        }

        internal override IMethodTableData GetMethodTableData(ulong addr)
        {
            if (_sos.GetMethodTableData(addr, out V45MethodTableData data) < 0)
                return null;

            return data;
        }

        internal override ulong GetMethodTableByEEClass(ulong eeclass)
        {
            if (_sos.GetMethodTableForEEClass(eeclass, out ulong value) != 0)
                return 0;

            return value;
        }

        internal override IGCInfo GetGCInfoImpl()
        {
            return (_sos.GetGCHeapData(out LegacyGCInfo gcInfo) >= 0) ? (IGCInfo)gcInfo : null;
        }

        internal override bool GetCommonMethodTables(ref CommonMethodTables mCommonMTs)
        {
            return _sos.GetUsefulGlobals(out mCommonMTs) >= 0;
        }

        internal override string GetNameForMT(ulong mt)
        {
            if (_sos.GetMethodTableName(mt, 0, null, out uint count) < 0)
                return null;

            StringBuilder sb = new StringBuilder((int)count);
            if (_sos.GetMethodTableName(mt, count, sb, out count) < 0)
                return null;

            return sb.ToString();
        }

        internal override string GetPEFileName(ulong addr)
        {
            if (_sos.GetPEFileName(addr, 0, null, out uint needed) < 0)
                return null;

            StringBuilder sb = new StringBuilder((int)needed);
            if (_sos.GetPEFileName(addr, needed, sb, out needed) < 0)
                return null;

            return sb.ToString();
        }

        internal override IModuleData GetModuleData(ulong addr)
        {
            return _sos.GetModuleData(addr, out V45ModuleData data) >= 0 ? (IModuleData)data : null;
        }

        internal override ulong GetModuleForMT(ulong addr)
        {
            if (_sos.GetMethodTableData(addr, out V45MethodTableData data) < 0)
                return 0;

            return data.module;
        }

        internal override ISegmentData GetSegmentData(ulong addr)
        {
            if (_sos.GetHeapSegmentData(addr, out V4SegmentData seg) < 0)
                return null;
            return seg;
        }

        internal override IAppDomainData GetAppDomainData(ulong addr)
        {
            LegacyAppDomainData data = new LegacyAppDomainData(); ;
            if (_sos.GetAppDomainData(addr, out data) < 0)
            {
                // We can face an exception while walking domain data if we catch the process
                // at a bad state.  As a workaround we will return partial data if data.Address
                // and data.StubHeap are set.
                if (data.Address != addr && data.StubHeap != 0)
                    return null;
            }

            return data;
        }

        internal override string GetAppDomaminName(ulong addr)
        {
            if (_sos.GetAppDomainName(addr, 0, null, out uint count) < 0)
                return null;

            StringBuilder sb = new StringBuilder((int)count);

            if (_sos.GetAppDomainName(addr, count, sb, out count) < 0)
                return null;

            return sb.ToString();
        }

        internal override string GetAssemblyName(ulong addr)
        {
            if (_sos.GetAssemblyName(addr, 0, null, out uint count) < 0)
                return null;

            StringBuilder sb = new StringBuilder((int)count);

            if (_sos.GetAssemblyName(addr, count, sb, out count) < 0)
                return null;

            return sb.ToString();
        }

        internal override bool TraverseHeap(ulong heap, DesktopRuntimeBase.LoaderHeapTraverse callback)
        {
            bool res = _sos.TraverseLoaderHeap(heap, Marshal.GetFunctionPointerForDelegate(callback)) >= 0;
            GC.KeepAlive(callback);
            return res;
        }

        internal override bool TraverseStubHeap(ulong appDomain, int type, DesktopRuntimeBase.LoaderHeapTraverse callback)
        {
            bool res = _sos.TraverseVirtCallStubHeap(appDomain, (uint)type, Marshal.GetFunctionPointerForDelegate(callback)) >= 0;
            GC.KeepAlive(callback);
            return res;
        }

        internal override IEnumerable<ICodeHeap> EnumerateJitHeaps()
        {
            LegacyJitManagerInfo[] jitManagers = null;

            int res = _sos.GetJitManagerList(0, null, out uint needed);
            if (res >= 0)
            {
                jitManagers = new LegacyJitManagerInfo[needed];
                res = _sos.GetJitManagerList(needed, jitManagers, out needed);
            }

            if (res >= 0 && jitManagers != null)
            {
                for (int i = 0; i < jitManagers.Length; ++i)
                {
                    if (jitManagers[i].type != CodeHeapType.Unknown)
                        continue;

                    res = _sos.GetCodeHeapList(jitManagers[i].addr, 0, null, out needed);
                    if (res >= 0 && needed > 0)
                    {
                        LegacyJitCodeHeapInfo[] heapInfo = new LegacyJitCodeHeapInfo[needed];
                        res = _sos.GetCodeHeapList(jitManagers[i].addr, needed, heapInfo, out needed);

                        if (res >= 0)
                        {
                            for (int j = 0; j < heapInfo.Length; ++j)
                            {
                                yield return (ICodeHeap)heapInfo[i];
                            }
                        }
                    }
                }
            }
        }

        internal override IFieldInfo GetFieldInfo(ulong mt)
        {
            if (_sos.GetMethodTableFieldData(mt, out V4FieldInfo fieldInfo) < 0)
                return null;

            return fieldInfo;
        }

        internal override IFieldData GetFieldData(ulong fieldDesc)
        {
            if (_sos.GetFieldDescData(fieldDesc, out LegacyFieldData data) < 0)
                return null;

            return data;
        }

        internal override ICorDebug.IMetadataImport GetMetadataImport(ulong module)
        {
            if (module == 0 || _sos.GetModule(module, out object obj) < 0)
                return null;

            RegisterForRelease(obj);
            return obj as ICorDebug.IMetadataImport;
        }

        internal override IObjectData GetObjectData(ulong objRef)
        {
            if (_sos.GetObjectData(objRef, out V45ObjectData data) < 0)
                return null;
            return data;
        }

        internal override IList<MethodTableTokenPair> GetMethodTableList(ulong module)
        {
            List<MethodTableTokenPair> mts = new List<MethodTableTokenPair>();
            int res = _sos.TraverseModuleMap(0, module, new ModuleMapTraverse(delegate (uint index, ulong mt, IntPtr token)
                { mts.Add(new MethodTableTokenPair(mt, index)); }),
                IntPtr.Zero);

            return mts;
        }

        internal override IDomainLocalModuleData GetDomainLocalModule(ulong appDomain, ulong id)
        {
            int res = _sos.GetDomainLocalModuleDataFromAppDomain(appDomain, (int)id, out V45DomainLocalModuleData data);
            if (res < 0)
                return null;

            return data;
        }

        internal override COMInterfacePointerData[] GetCCWInterfaces(ulong ccw, int count)
        {
            COMInterfacePointerData[] data = new COMInterfacePointerData[count];
            if (_sos.GetCCWInterfaces(ccw, (uint)count, data, out uint pNeeded) >= 0)
                return data;

            return null;
        }

        internal override COMInterfacePointerData[] GetRCWInterfaces(ulong rcw, int count)
        {
            COMInterfacePointerData[] data = new COMInterfacePointerData[count];
            if (_sos.GetRCWInterfaces(rcw, (uint)count, data, out uint pNeeded) >= 0)
                return data;

            return null;
        }
        internal override ICCWData GetCCWData(ulong ccw)
        {
            if (ccw != 0 && _sos.GetCCWData(ccw, out V45CCWData data) >= 0)
                return data;

            return null;
        }

        internal override IRCWData GetRCWData(ulong rcw)
        {
            if (rcw != 0 && _sos.GetRCWData(rcw, out V45RCWData data) >= 0)
                return data;

            return null;
        }
        #endregion

        internal override ulong GetILForModule(ClrModule module, uint rva)
        {
            return _sos.GetILForModule(module.Address, rva, out ulong ilAddr) == 0 ? ilAddr : 0;
        }

        internal override ulong GetThreadStaticPointer(ulong thread, ClrElementType type, uint offset, uint moduleId, bool shared)
        {
            ulong addr = offset;

            if (_sos.GetThreadLocalModuleData(thread, moduleId, out V45ThreadLocalModuleData data) < 0)
                return 0;

            if (IsObjectReference(type) || IsValueClass(type))
                addr += data.pGCStaticDataStart;
            else
                addr += data.pNonGCStaticDataStart;

            return addr;
        }

        internal override IDomainLocalModuleData GetDomainLocalModule(ulong module)
        {
            if (_sos.GetDomainLocalModuleDataFromModule(module, out V45DomainLocalModuleData data) < 0)
                return null;

            return data;
        }

        internal override IList<ulong> GetMethodDescList(ulong methodTable)
        {
            if (_sos.GetMethodTableData(methodTable, out V45MethodTableData mtData) < 0)
                return null;

            List<ulong> mds = new List<ulong>(mtData.wNumMethods);

            ulong ip = 0;
            for (uint i = 0; i < mtData.wNumMethods; ++i)
                if (_sos.GetMethodTableSlot(methodTable, i, out ip) >= 0)
                {
                    if (_sos.GetCodeHeaderData(ip, out CodeHeaderData header) >= 0)
                        mds.Add(header.MethodDescPtr);
                }

            return mds;
        }

        internal override string GetNameForMD(ulong md)
        {
            if (_sos.GetMethodDescName(md, 0, null, out uint needed) < 0)
                return "UNKNOWN";

            StringBuilder sb = new StringBuilder((int)needed);
            if (_sos.GetMethodDescName(md, (uint)sb.Capacity, sb, out uint actuallyNeeded) < 0)
                return "UNKNOWN";

            // Patch for a bug on sos side :
            //  Sometimes, when the target method has parameters with generic types
            //  the first call to GetMethodDescName sets an incorrect value into pNeeded.
            //  In those cases, a second call directly after the first returns the correct value.
            if (needed != actuallyNeeded)
            {
                sb.Capacity = (int)actuallyNeeded;
                if (_sos.GetMethodDescName(md, (uint)sb.Capacity, sb, out actuallyNeeded) < 0)
                    return "UNKNOWN";
            }

            return sb.ToString();
        }

        internal override IMethodDescData GetMethodDescData(ulong md)
        {
            V45MethodDescDataWrapper wrapper = new V45MethodDescDataWrapper();
            if (!wrapper.Init(_sos, md))
                return null;

            return wrapper;
        }

        internal override uint GetMetadataToken(ulong mt)
        {
            if (_sos.GetMethodTableData(mt, out V45MethodTableData data) < 0)
                return uint.MaxValue;

            return data.token;
        }

        protected override DesktopStackFrame GetStackFrame(DesktopThread thread, int res, ulong ip, ulong framePtr, ulong frameVtbl)
        {
            DesktopStackFrame frame;
            StringBuilder sb = new StringBuilder(256);
            if (res >= 0 && frameVtbl != 0)
            {
                ClrMethod innerMethod = null;
                string frameName = "Unknown Frame";
                if (_sos.GetFrameName(frameVtbl, (uint)sb.Capacity, sb, out uint needed) >= 0)
                    frameName = sb.ToString();

                if (_sos.GetMethodDescPtrFromFrame(framePtr, out ulong md) == 0)
                {
                    V45MethodDescDataWrapper mdData = new V45MethodDescDataWrapper();
                    if (mdData.Init(_sos, md))
                        innerMethod = DesktopMethod.Create(this, mdData);
                }

                frame = new DesktopStackFrame(this, thread, framePtr, frameName, innerMethod);
            }
            else
            {
                if (_sos.GetMethodDescPtrFromIP(ip, out ulong md) >= 0)
                {
                    frame = new DesktopStackFrame(this, thread, ip, framePtr, md);
                }
                else
                {
                    frame = new DesktopStackFrame(this, thread, ip, framePtr, 0);
                }
            }

            return frame;
        }

        private bool GetStackTraceFromField(ClrType type, ulong obj, out ulong stackTrace)
        {
            stackTrace = 0;
            var field = type.GetFieldByName("_stackTrace");
            if (field == null)
                return false;

            object tmp = field.GetValue(obj);
            if (tmp == null || !(tmp is ulong))
                return false;

            stackTrace = (ulong)tmp;
            return true;
        }


        internal override IList<ClrStackFrame> GetExceptionStackTrace(ulong obj, ClrType type)
        {
            // TODO: Review this and if it works on v4.5, merge the two implementations back into RuntimeBase.
            List<ClrStackFrame> result = new List<ClrStackFrame>();
            if (type == null)
                return result;

            if (!GetStackTraceFromField(type, obj, out ulong _stackTrace))
            {
                if (!ReadPointer(obj + GetStackTraceOffset(), out _stackTrace))
                    return result;
            }

            if (_stackTrace == 0)
                return result;

            ClrHeap heap = Heap;
            ClrType stackTraceType = heap.GetObjectType(_stackTrace);
            if (stackTraceType == null || !stackTraceType.IsArray)
                return result;

            int len = stackTraceType.GetArrayLength(_stackTrace);
            if (len == 0)
                return result;

            int elementSize = IntPtr.Size * 4;
            ulong dataPtr = _stackTrace + (ulong)(IntPtr.Size * 2);
            if (!ReadPointer(dataPtr, out ulong count))
                return result;

            // Skip size and header
            dataPtr += (ulong)(IntPtr.Size * 2);

            DesktopThread thread = null;
            for (int i = 0; i < (int)count; ++i)
            {
                if (!ReadPointer(dataPtr, out ulong ip))
                    break;
                if (!ReadPointer(dataPtr + (ulong)IntPtr.Size, out ulong sp))
                    break;
                if (!ReadPointer(dataPtr + (ulong)(2 * IntPtr.Size), out ulong md))
                    break;

                if (i == 0)
                    thread = (DesktopThread)GetThreadByStackAddress(sp);

                result.Add(new DesktopStackFrame(this, thread, ip, sp, md));

                dataPtr += (ulong)elementSize;
            }

            return result;
        }

        internal override IThreadStoreData GetThreadStoreData()
        {
            if (_sos.GetThreadStoreData(out LegacyThreadStoreData data) < 0)
                return null;

            return data;
        }

        internal override string GetAppBase(ulong appDomain)
        {
            if (_sos.GetApplicationBase(appDomain, 0, null, out uint needed) < 0)
                return null;

            StringBuilder builder = new StringBuilder((int)needed);
            if (_sos.GetApplicationBase(appDomain, (int)needed, builder, out needed) < 0)
                return null;

            return builder.ToString();
        }

        internal override string GetConfigFile(ulong appDomain)
        {
            if (_sos.GetAppDomainConfigFile(appDomain, 0, null, out uint needed) < 0)
                return null;

            StringBuilder builder = new StringBuilder((int)needed);
            if (_sos.GetAppDomainConfigFile(appDomain, (int)needed, builder, out needed) < 0)
                return null;

            return builder.ToString();
        }

        internal override IMethodDescData GetMDForIP(ulong ip)
        {
            if (_sos.GetMethodDescPtrFromIP(ip, out ulong md) < 0 || md == 0)
            {
                if (_sos.GetCodeHeaderData(ip, out CodeHeaderData codeHeaderData) < 0)
                    return null;

                if ((md = codeHeaderData.MethodDescPtr) == 0)
                    return null;
            }

            V45MethodDescDataWrapper mdWrapper = new V45MethodDescDataWrapper();
            if (!mdWrapper.Init(_sos, md))
                return null;

            return mdWrapper;
        }

        protected override ulong GetThreadFromThinlock(uint threadId)
        {
            if (_sos.GetThreadFromThinlockID(threadId, out ulong thread) < 0)
                return 0;

            return thread;
        }

        internal override int GetSyncblkCount()
        {
            if (_sos.GetSyncBlockData(1, out LegacySyncBlkData data) < 0)
                return 0;

            return (int)data.TotalCount;
        }

        internal override ISyncBlkData GetSyncblkData(int index)
        {
            if (_sos.GetSyncBlockData((uint)index + 1, out LegacySyncBlkData data) < 0)
                return null;

            return data;
        }

        internal override IThreadPoolData GetThreadPoolData()
        {
            if (_sos.GetThreadpoolData(out V45ThreadPoolData data) < 0)
                return null;

            return data;
        }

        internal override uint GetTlsSlot()
        {
            if (_sos.GetTLSIndex(out uint result) < 0)
                return uint.MaxValue;

            return result;
        }

        internal override uint GetThreadTypeIndex()
        {
            return 11;
        }

        protected override uint GetRWLockDataOffset()
        {
            if (PointerSize == 8)
                return 0x30;
            else
                return 0x18;
        }

        internal override IEnumerable<NativeWorkItem> EnumerateWorkItems()
        {
            if (_sos.GetThreadpoolData(out V45ThreadPoolData data) == 0)
            {
                ulong request = data.FirstWorkRequest;
                while (request != 0)
                {
                    if (_sos.GetWorkRequestData(request, out V45WorkRequestData requestData) != 0)
                        break;

                    yield return new DesktopNativeWorkItem(requestData);
                    request = requestData.NextWorkRequest;
                }
            }
        }

        internal override uint GetStringFirstCharOffset()
        {
            if (PointerSize == 8)
                return 0xc;

            return 8;
        }

        internal override uint GetStringLengthOffset()
        {
            if (PointerSize == 8)
                return 0x8;

            return 0x4;
        }

        internal override uint GetExceptionHROffset()
        {
            return PointerSize == 8 ? 0x8cu : 0x40u;
        }
    }


    
}
