// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Diagnostics.Runtime.Private
{

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("3E269830-4A2B-4301-8EE2-D6805B29B2FA")]
    public interface ISOSHandleEnum
    {
        void Skip(uint count);
        void Reset();
        void GetCount(out uint count);
        [PreserveSig]
        int Next(uint count, [Out, MarshalAs(UnmanagedType.LPArray)] HandleData[] handles, out uint pNeeded);
    }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("8FA642BD-9F10-4799-9AA3-512AE78C77EE")]
    public interface ISOSStackRefEnum
    {
        void Skip(uint count);
        void Reset();
        void GetCount(out uint count);
        [PreserveSig]
        int Next(uint count, [Out, MarshalAs(UnmanagedType.LPArray)] StackRefData[] handles, out uint pNeeded);
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void ModuleMapTraverse(uint index, ulong methodTable, IntPtr token);

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("436f00f2-b42a-4b9f-870c-e73db66ae930")]
    public interface ISOSDac
    {
        // ThreadStore
        [PreserveSig]
        int GetThreadStoreData(out LegacyThreadStoreData data);

        // AppDomains
        [PreserveSig]
        int GetAppDomainStoreData(out LegacyAppDomainStoreData data);
        [PreserveSig]
        int GetAppDomainList(uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]ulong[] values, out uint pNeeded);
        [PreserveSig]
        int GetAppDomainData(ulong addr, out LegacyAppDomainData data);
        [PreserveSig]
        int GetAppDomainName(ulong addr, uint count, [Out]StringBuilder lpFilename, out uint pNeeded);
        [PreserveSig]
        int GetDomainFromContext(ulong context, out ulong domain);

        // Assemblies
        [PreserveSig]
        int GetAssemblyList(ulong appDomain, int count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] ulong[] values, out int pNeeded);
        [PreserveSig]
        int GetAssemblyData(ulong baseDomainPtr, ulong assembly, out LegacyAssemblyData data);
        [PreserveSig]
        int GetAssemblyName(ulong assembly, uint count, [Out] StringBuilder name, out uint pNeeded);

        // Modules
        [PreserveSig]
        int GetModule(ulong addr, [Out, MarshalAs(UnmanagedType.IUnknown)] out object module);
        [PreserveSig]
        int GetModuleData(ulong moduleAddr, out V45ModuleData data);
        [PreserveSig]
        int TraverseModuleMap(int mmt, ulong moduleAddr, [In, MarshalAs(UnmanagedType.FunctionPtr)] ModuleMapTraverse pCallback, IntPtr token);
        [PreserveSig]
        int GetAssemblyModuleList(ulong assembly, uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] ulong[] modules, out uint pNeeded);
        [PreserveSig]
        int GetILForModule(ulong moduleAddr, uint rva, out ulong il);

        // Threads
        [PreserveSig]
        int GetThreadData(ulong thread, out V4ThreadData data);
        [PreserveSig]
        int GetThreadFromThinlockID(uint thinLockId, out ulong pThread);
        [PreserveSig]
        int GetStackLimits(ulong threadPtr, out ulong lower, out ulong upper, out ulong fp);

        // MethodDescs
        [PreserveSig]
        int GetMethodDescData(ulong methodDesc, ulong ip, out V45MethodDescData data, uint cRevertedRejitVersions, V45ReJitData[] rgRevertedRejitData, out ulong pcNeededRevertedRejitData);
        [PreserveSig]
        int GetMethodDescPtrFromIP(ulong ip, out ulong ppMD);
        [PreserveSig]
        int GetMethodDescName(ulong methodDesc, uint count, [Out] StringBuilder name, out uint pNeeded);
        [PreserveSig]
        int GetMethodDescPtrFromFrame(ulong frameAddr, out ulong ppMD);
        [PreserveSig]
        int GetMethodDescFromToken(ulong moduleAddr, uint token, out ulong methodDesc);
        [PreserveSig]
        int GetMethodDescTransparencyData_do_not_use();//(ulong methodDesc, out DacpMethodDescTransparencyData data);

        // JIT Data
        [PreserveSig]
        int GetCodeHeaderData(ulong ip, out CodeHeaderData data);
        [PreserveSig]
        int GetJitManagerList(uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] LegacyJitManagerInfo[] jitManagers, out uint pNeeded);
        [PreserveSig]
        int GetJitHelperFunctionName(ulong ip, uint count, char name, out uint pNeeded);
        [PreserveSig]
        int GetJumpThunkTarget_do_not_use(uint ctx, out ulong targetIP, out ulong targetMD);

        // ThreadPool
        [PreserveSig]
        int GetThreadpoolData(out V45ThreadPoolData data);
        [PreserveSig]
        int GetWorkRequestData(ulong addrWorkRequest, out V45WorkRequestData data);
        [PreserveSig]
        int GetHillClimbingLogEntry_do_not_use(); //(ulong addr, out DacpHillClimbingLogEntry data);

        // Objects
        [PreserveSig]
        int GetObjectData(ulong objAddr, out V45ObjectData data);
        [PreserveSig]
        int GetObjectStringData(ulong obj, uint count, [Out] StringBuilder stringData, out uint pNeeded);
        [PreserveSig]
        int GetObjectClassName(ulong obj, uint count, [Out] StringBuilder className, out uint pNeeded);

        // MethodTable
        [PreserveSig]
        int GetMethodTableName(ulong mt, uint count, [Out] StringBuilder mtName, out uint pNeeded);
        [PreserveSig]
        int GetMethodTableData(ulong mt, out V45MethodTableData data);
        [PreserveSig]
        int GetMethodTableSlot(ulong mt, uint slot, out ulong value);
        [PreserveSig]
        int GetMethodTableFieldData(ulong mt, out V4FieldInfo data);
        [PreserveSig]
        int GetMethodTableTransparencyData_do_not_use(); //(ulong mt, out DacpMethodTableTransparencyData data);

        // EEClass
        [PreserveSig]
        int GetMethodTableForEEClass(ulong eeClass, out ulong value);

        // FieldDesc
        [PreserveSig]
        int GetFieldDescData(ulong fieldDesc, out LegacyFieldData data);

        // Frames
        [PreserveSig]
        int GetFrameName(ulong vtable, uint count, [Out] StringBuilder frameName, out uint pNeeded);


        // PEFiles
        [PreserveSig]
        int GetPEFileBase(ulong addr, [Out] out ulong baseAddr);

        [PreserveSig]
        int GetPEFileName(ulong addr, uint count, [Out] StringBuilder ptr, [Out] out uint pNeeded);

        // GC
        [PreserveSig]
        int GetGCHeapData(out LegacyGCInfo data);
        [PreserveSig]
        int GetGCHeapList(uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] ulong[] heaps, out uint pNeeded); // svr only
        [PreserveSig]
        int GetGCHeapDetails(ulong heap, out V4HeapDetails details); // wks only
        [PreserveSig]
        int GetGCHeapStaticData(out V4HeapDetails data);
        [PreserveSig]
        int GetHeapSegmentData(ulong seg, out V4SegmentData data);
        [PreserveSig]
        int GetOOMData_do_not_use(); //(ulong oomAddr, out DacpOomData data);
        [PreserveSig]
        int GetOOMStaticData_do_not_use(); //(out DacpOomData data);
        [PreserveSig]
        int GetHeapAnalyzeData_do_not_use(); //(ulong addr, out  DacpGcHeapAnalyzeData data);
        [PreserveSig]
        int GetHeapAnalyzeStaticData_do_not_use(); //(out DacpGcHeapAnalyzeData data);

        // DomainLocal
        [PreserveSig]
        int GetDomainLocalModuleData_do_not_use(); //(ulong addr, out DacpDomainLocalModuleData data);
        [PreserveSig]
        int GetDomainLocalModuleDataFromAppDomain(ulong appDomainAddr, int moduleID, out V45DomainLocalModuleData data);
        [PreserveSig]
        int GetDomainLocalModuleDataFromModule(ulong moduleAddr, out V45DomainLocalModuleData data);

        // ThreadLocal
        [PreserveSig]
        int GetThreadLocalModuleData(ulong thread, uint index, out V45ThreadLocalModuleData data);

        // SyncBlock
        [PreserveSig]
        int GetSyncBlockData(uint number, out LegacySyncBlkData data);
        [PreserveSig]
        int GetSyncBlockCleanupData_do_not_use(); //(ulong addr, out DacpSyncBlockCleanupData data);

        // Handles
        [PreserveSig]
        int GetHandleEnum([Out, MarshalAs(UnmanagedType.IUnknown)] out object ppHandleEnum);
        [PreserveSig]
        int GetHandleEnumForTypes([In] uint[] types, uint count, [Out, MarshalAs(UnmanagedType.IUnknown)] out object ppHandleEnum);
        [PreserveSig]
        int GetHandleEnumForGC(uint gen, [Out, MarshalAs(UnmanagedType.IUnknown)] out object ppHandleEnum);

        // EH
        [PreserveSig]
        int TraverseEHInfo_do_not_use(); //(ulong ip, DUMPEHINFO pCallback, IntPtr token);
        [PreserveSig]
        int GetNestedExceptionData(ulong exception, out ulong exceptionObject, out ulong nextNestedException);

        // StressLog
        [PreserveSig]
        int GetStressLogAddress(out ulong stressLog);

        // Heaps
        [PreserveSig]
        int TraverseLoaderHeap(ulong loaderHeapAddr, IntPtr pCallback);
        [PreserveSig]
        int GetCodeHeapList(ulong jitManager, uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] LegacyJitCodeHeapInfo[] codeHeaps, out uint pNeeded);
        [PreserveSig]
        int TraverseVirtCallStubHeap(ulong pAppDomain, uint heaptype, IntPtr pCallback);

        // Other
        [PreserveSig]
        int GetUsefulGlobals(out CommonMethodTables data);
        [PreserveSig]
        int GetClrWatsonBuckets(ulong thread, out IntPtr pGenericModeBlock);
        [PreserveSig]
        int GetTLSIndex(out uint pIndex);
        [PreserveSig]
        int GetDacModuleHandle(out IntPtr phModule);

        // COM
        [PreserveSig]
        int GetRCWData(ulong addr, out V45RCWData data);
        [PreserveSig]
        int GetRCWInterfaces(ulong rcw, uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] COMInterfacePointerData[] interfaces, out uint pNeeded);
        [PreserveSig]
        int GetCCWData(ulong ccw, out V45CCWData data);
        [PreserveSig]
        int GetCCWInterfaces(ulong ccw, uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] COMInterfacePointerData[] interfaces, out uint pNeeded);
        [PreserveSig]
        int TraverseRCWCleanupList_do_not_use(); //(ulong cleanupListPtr, VISITRCWFORCLEANUP pCallback, LPVOID token);

        // GC Reference Functions
        [PreserveSig]
        int GetStackReferences(uint osThreadID, [Out, MarshalAs(UnmanagedType.IUnknown)] out object ppEnum);
        [PreserveSig]
        int GetRegisterName(int regName, uint count, [Out] StringBuilder buffer, out uint pNeeded);


        [PreserveSig]
        int GetThreadAllocData(ulong thread, ref V45AllocData data);
        [PreserveSig]
        int GetHeapAllocData(uint count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] V45GenerationAllocData[] data, out uint pNeeded);

        // For BindingDisplay plugin
        [PreserveSig]
        int GetFailedAssemblyList(ulong appDomain, int count, ulong[] values, out uint pNeeded);
        [PreserveSig]
        int GetPrivateBinPaths(ulong appDomain, int count, [Out] StringBuilder paths, out uint pNeeded);
        [PreserveSig]
        int GetAssemblyLocation(ulong assembly, int count, [Out] StringBuilder location, out uint pNeeded);
        [PreserveSig]
        int GetAppDomainConfigFile(ulong appDomain, int count, [Out] StringBuilder configFile, out uint pNeeded);
        [PreserveSig]
        int GetApplicationBase(ulong appDomain, int count, [Out] StringBuilder appBase, out uint pNeeded);
        [PreserveSig]
        int GetFailedAssemblyData(ulong assembly, out uint pContext, out int pResult);
        [PreserveSig]
        int GetFailedAssemblyLocation(ulong assesmbly, uint count, [Out] StringBuilder location, out uint pNeeded);
        [PreserveSig]
        int GetFailedAssemblyDisplayName(ulong assembly, uint count, [Out] StringBuilder name, out uint pNeeded);
    }



#pragma warning disable 0649
#pragma warning disable 0169
    
    public struct V45ThreadPoolData : IThreadPoolData
    {
        private int _cpuUtilization;
        private int _numIdleWorkerThreads;
        private int _numWorkingWorkerThreads;
        private int _numRetiredWorkerThreads;
        private int _minLimitTotalWorkerThreads;
        private int _maxLimitTotalWorkerThreads;

        private ulong _firstUnmanagedWorkRequest;

        private ulong _hillClimbingLog;
        private int _hillClimbingLogFirstIndex;
        private int _hillClimbingLogSize;

        private int _numTimers;

        private int _numCPThreads;
        private int _numFreeCPThreads;
        private int _maxFreeCPThreads;
        private int _numRetiredCPThreads;
        private int _maxLimitTotalCPThreads;
        private int _currentLimitTotalCPThreads;
        private int _minLimitTotalCPThreads;

        private ulong _asyncTimerCallbackCompletionFPtr;

        public int MinCP
        {
            get { return _minLimitTotalCPThreads; }
        }

        public int MaxCP
        {
            get { return _maxLimitTotalCPThreads; }
        }

        public int CPU
        {
            get { return _cpuUtilization; }
        }

        public int NumFreeCP
        {
            get { return _numFreeCPThreads; }
        }

        public int MaxFreeCP
        {
            get { return _maxFreeCPThreads; }
        }

        public int TotalThreads
        {
            get { return _numIdleWorkerThreads + _numWorkingWorkerThreads + _numRetiredWorkerThreads; }
        }

        public int RunningThreads
        {
            get { return _numWorkingWorkerThreads; }
        }

        public int IdleThreads
        {
            get { return _numIdleWorkerThreads; }
        }

        public int MinThreads
        {
            get { return _minLimitTotalWorkerThreads; }
        }

        public int MaxThreads
        {
            get { return _maxLimitTotalWorkerThreads; }
        }


        public ulong FirstWorkRequest
        {
            get { return _firstUnmanagedWorkRequest; }
        }


        public ulong QueueUserWorkItemCallbackFPtr
        {
            get { return ulong.MaxValue; }
        }

        public ulong AsyncCallbackCompletionFPtr
        {
            get { return ulong.MaxValue; }
        }

        ulong IThreadPoolData.AsyncTimerCallbackCompletionFPtr
        {
            get { return ulong.MaxValue; }
        }
    }

    public struct V45ThreadLocalModuleData
    {
        private ulong _threadAddr;
        private ulong _moduleIndex;

        private ulong _pClassData;
        private ulong _pDynamicClassTable;
        public ulong pGCStaticDataStart;
        public ulong pNonGCStaticDataStart;
    }

    public struct V45DomainLocalModuleData : IDomainLocalModuleData
    {
        private ulong _appDomainAddr;
        private ulong _moduleID;

        private ulong _pClassData;
        private ulong _pDynamicClassTable;
        private ulong _pGCStaticDataStart;
        private ulong _pNonGCStaticDataStart;

        public ulong AppDomainAddr
        {
            get { return _appDomainAddr; }
        }

        public ulong ModuleID
        {
            get { return _moduleID; }
        }

        public ulong ClassData
        {
            get { return _pClassData; }
        }

        public ulong DynamicClassTable
        {
            get { return _pDynamicClassTable; }
        }

        public ulong GCStaticDataStart
        {
            get { return _pGCStaticDataStart; }
        }

        public ulong NonGCStaticDataStart
        {
            get { return _pNonGCStaticDataStart; }
        }
    }

    public struct StackRefData
    {
        public uint HasRegisterInformation;
        public int Register;
        public int Offset;
        public ulong _address;
        public ulong _object;
        public uint Flags;

        public uint SourceType;
        public ulong Source;
        public ulong _stackPointer;

        public ulong Address => FixSignExtension(_address);
        public ulong Object => FixSignExtension(_object);
        public ulong StackPointer => FixSignExtension(_stackPointer);

        private ulong FixSignExtension(ulong ptr)
        {
            const ulong high = 0xffffffff00000000;

            if (IntPtr.Size == 4 && (ptr & high) == high)
                return ptr & ~high;

            return ptr;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct HandleData
    {
        public ulong AppDomain;
        public ulong Handle;
        public ulong Secondary;
        public uint Type;
        public uint StrongReference;

        // For RefCounted Handles
        public uint RefCount;
        public uint JupiterRefCount;
        public uint IsPegged;
    }

    public struct V45ReJitData
    {
        private ulong _rejitID;
        private uint _flags;
        private ulong _nativeCodeAddr;
    }

    internal enum MethodCompilationType
    {
        None,
        Jit,
        Ngen
    }

    public class V45MethodDescDataWrapper : IMethodDescData
    {

        public bool Init(ISOSDac sos, ulong md)
        {
            V45MethodDescData data = new V45MethodDescData();
            if (sos.GetMethodDescData(md, 0, out data, 0, null, out ulong count) < 0)
                return false;

            _md = data.MethodDescPtr;
            _ip = data.NativeCodeAddr;
            _module = data.ModulePtr;
            _token = data.MDToken;
            _mt = data.MethodTablePtr;

            if (sos.GetCodeHeaderData(data.NativeCodeAddr, out CodeHeaderData header) >= 0)
            {
                if (header.JITType == 1)
                    _jitType = (int)MethodCompilationType.Jit;
                else if (header.JITType == 2)
                    _jitType = (int)MethodCompilationType.Ngen;
                else
                    _jitType = (int)MethodCompilationType.None;

                _gcInfo = header.GCInfo;
                _coldStart = header.ColdRegionStart;
                _coldSize = header.ColdRegionSize;
                _hotSize = header.HotRegionSize;
            }
            else
            {
                _jitType = (int)MethodCompilationType.None;
            }

            return true;
        }

        private int _jitType;
        private ulong _gcInfo, _md, _module, _ip, _coldStart;
        private uint _token, _coldSize, _hotSize;
        private ulong _mt;

        public ulong GCInfo
        {
            get
            {
                return _gcInfo;
            }
        }

        public ulong MethodDesc
        {
            get { return _md; }
        }

        public ulong Module
        {
            get { return _module; }
        }

        public uint MDToken
        {
            get { return _token; }
        }

        public ulong NativeCodeAddr
        {
            get { return _ip; }
        }

        public int JITType
        {
            get { return _jitType; }
        }


        public ulong MethodTable
        {
            get { return _mt; }
        }

        public ulong ColdStart
        {
            get { return _coldStart; }
        }

        public uint ColdSize
        {
            get { return _coldSize; }
        }

        public uint HotSize
        {
            get { return _hotSize; }
        }
    }

    public struct V45MethodDescData
    {
        private uint _bHasNativeCode;
        private uint _bIsDynamic;
        private short _wSlotNumber;
        public ulong NativeCodeAddr;
        // Useful for breaking when a method is jitted.
        private ulong _addressOfNativeCodeSlot;

        public ulong MethodDescPtr;
        public ulong MethodTablePtr;
        public ulong ModulePtr;

        public uint MDToken;
        public ulong GCInfo;
        private ulong _GCStressCodeCopy;

        // This is only valid if bIsDynamic is true
        private ulong _managedDynamicMethodObject;

        private ulong _requestedIP;

        // Gives info for the single currently active version of a method
        private V45ReJitData _rejitDataCurrent;

        // Gives info corresponding to requestedIP (for !ip2md)
        private V45ReJitData _rejitDataRequested;

        // Total number of rejit versions that have been jitted
        private uint _cJittedRejitVersions;
    }

    public struct CodeHeaderData
    {
        public ulong GCInfo;
        public uint JITType;
        public ulong MethodDescPtr;
        public ulong MethodStart;
        public uint MethodSize;
        public ulong ColdRegionStart;
        public uint ColdRegionSize;
        public uint HotRegionSize;
    }

    public struct V45ModuleData : IModuleData
    {
        public ulong address;
        public ulong peFile;
        public ulong ilBase;
        public ulong metadataStart;
        public ulong metadataSize;
        public ulong assembly;
        public uint bIsReflection;
        public uint bIsPEFile;
        public ulong dwBaseClassIndex;
        public ulong dwModuleID;
        public uint dwTransientFlags;
        public ulong TypeDefToMethodTableMap;
        public ulong TypeRefToMethodTableMap;
        public ulong MethodDefToDescMap;
        public ulong FieldDefToDescMap;
        public ulong MemberRefToDescMap;
        public ulong FileReferencesMap;
        public ulong ManifestModuleReferencesMap;
        public ulong pLookupTableHeap;
        public ulong pThunkHeap;
        public ulong dwModuleIndex;

        #region IModuleData
        public ulong Assembly
        {
            get
            {
                return assembly;
            }
        }

        public ulong PEFile
        {
            get
            {
                return (bIsPEFile == 0) ? ilBase : peFile;
            }
        }
        public ulong LookupTableHeap
        {
            get { return pLookupTableHeap; }
        }
        public ulong ThunkHeap
        {
            get { return pThunkHeap; }
        }


        public object LegacyMetaDataImport
        {
            get { return null; }
        }


        public ulong ModuleId
        {
            get { return dwModuleID; }
        }

        public ulong ModuleIndex
        {
            get { return dwModuleIndex; }
        }

        public bool IsReflection
        {
            get { return bIsReflection != 0; }
        }

        public bool IsPEFile
        {
            get { return bIsPEFile != 0; }
        }
        public ulong ImageBase
        {
            get { return ilBase; }
        }
        public ulong MetdataStart
        {
            get { return metadataStart; }
        }

        public ulong MetadataLength
        {
            get { return metadataSize; }
        }
        #endregion
    }

    public struct V45ObjectData : IObjectData
    {
        private ulong _methodTable;
        private uint _objectType;
        private ulong _size;
        private ulong _elementTypeHandle;
        private uint _elementType;
        private uint _dwRank;
        private ulong _dwNumComponents;
        private ulong _dwComponentSize;
        private ulong _arrayDataPtr;
        private ulong _arrayBoundsPtr;
        private ulong _arrayLowerBoundsPtr;

        private ulong _rcw;
        private ulong _ccw;

        public uint ElementType { get { return _elementType; } }
        public ulong ElementTypeHandle { get { return _elementTypeHandle; } }
        public ulong RCW { get { return _rcw; } }
        public ulong CCW { get { return _ccw; } }

        public ulong DataPointer
        {
            get { return _arrayDataPtr; }
        }
    }

    public struct V45MethodTableData : IMethodTableData
    {
        public uint bIsFree; // everything else is NULL if this is true.
        public ulong module;
        public ulong eeClass;
        public ulong parentMethodTable;
        public ushort wNumInterfaces;
        public ushort wNumMethods;
        public ushort wNumVtableSlots;
        public ushort wNumVirtuals;
        public uint baseSize;
        public uint componentSize;
        public uint token;
        public uint dwAttrClass;
        public uint isShared; // flags & enum_flag_DomainNeutral
        public uint isDynamic;
        public uint containsPointers;

        public bool ContainsPointers
        {
            get { return containsPointers != 0; }
        }

        public uint BaseSize
        {
            get { return baseSize; }
        }

        public uint ComponentSize
        {
            get { return componentSize; }
        }

        public ulong EEClass
        {
            get { return eeClass; }
        }

        public bool Free
        {
            get { return bIsFree != 0; }
        }

        public ulong Parent
        {
            get { return parentMethodTable; }
        }

        public bool Shared
        {
            get { return isShared != 0; }
        }


        public uint NumMethods
        {
            get { return wNumMethods; }
        }


        public ulong ElementTypeHandle
        {
            get { throw new NotImplementedException(); }
        }
    }

    public struct V45CCWData : ICCWData
    {
        private ulong _outerIUnknown;
        private ulong _managedObject;
        private ulong _handle;
        private ulong _ccwAddress;

        private int _refCount;
        private int _interfaceCount;
        private uint _isNeutered;

        private int _jupiterRefCount;
        private uint _isPegged;
        private uint _isGlobalPegged;
        private uint _hasStrongRef;
        private uint _isExtendsCOMObject;
        private uint _hasWeakReference;
        private uint _isAggregated;

        public ulong IUnknown
        {
            get { return _outerIUnknown; }
        }

        public ulong Object
        {
            get { return _managedObject; }
        }

        public ulong Handle
        {
            get { return _handle; }
        }

        public ulong CCWAddress
        {
            get { return _ccwAddress; }
        }

        public int RefCount
        {
            get { return _refCount; }
        }

        public int JupiterRefCount
        {
            get { return _jupiterRefCount; }
        }

        public int InterfaceCount
        {
            get { return _interfaceCount; }
        }
    }

    public struct COMInterfacePointerData
    {
        public ulong MethodTable;
        public ulong InterfacePtr;
        public ulong ComContext;
    }

    public struct V45RCWData : IRCWData
    {
        private ulong _identityPointer;
        private ulong _unknownPointer;
        private ulong _managedObject;
        private ulong _jupiterObject;
        private ulong _vtablePtr;
        private ulong _creatorThread;
        private ulong _ctxCookie;

        private int _refCount;
        private int _interfaceCount;

        private uint _isJupiterObject;
        private uint _supportsIInspectable;
        private uint _isAggregated;
        private uint _isContained;
        private uint _isFreeThreaded;
        private uint _isDisconnected;

        public ulong IdentityPointer
        {
            get { return _identityPointer; }
        }

        public ulong UnknownPointer
        {
            get { return _unknownPointer; }
        }

        public ulong ManagedObject
        {
            get { return _managedObject; }
        }

        public ulong JupiterObject
        {
            get { return _jupiterObject; }
        }

        public ulong VTablePtr
        {
            get { return _vtablePtr; }
        }

        public ulong CreatorThread
        {
            get { return _creatorThread; }
        }

        public int RefCount
        {
            get { return _refCount; }
        }

        public int InterfaceCount
        {
            get { return _interfaceCount; }
        }

        public bool IsJupiterObject
        {
            get { return _isJupiterObject != 0; }
        }

        public bool IsDisconnected
        {
            get { return _isDisconnected != 0; }
        }
    }


    public struct V45WorkRequestData
    {
        public ulong Function;
        public ulong Context;
        public ulong NextWorkRequest;
    }

#pragma warning restore 0169
#pragma warning restore 0649
}
