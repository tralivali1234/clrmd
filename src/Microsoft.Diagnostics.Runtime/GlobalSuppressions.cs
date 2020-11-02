﻿// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.IBinaryLocator.FindBinary(System.String,System.Int32,System.Int32,System.Boolean)~System.String")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.IBinaryLocator.FindBinaryAsync(System.String,System.Int32,System.Int32,System.Boolean)~System.Threading.Tasks.Task{System.String}")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.IBinaryLocator.FindBinary(System.String,System.Collections.Immutable.ImmutableArray{System.Byte},System.Boolean)~System.String")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.IBinaryLocator.FindBinaryAsync(System.String,System.Collections.Immutable.ImmutableArray{System.Byte},System.Boolean)~System.Threading.Tasks.Task{System.String}")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.GCRoot.EnumerateGCRoots(System.UInt64,System.Boolean,System.Int32,System.Collections.Generic.IEnumerable{Microsoft.Diagnostics.Runtime.IClrRoot},System.Threading.CancellationToken)~System.Collections.Generic.IEnumerable{Microsoft.Diagnostics.Runtime.GCRootPath}")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.GCRoot.EnumerateGCRoots(System.UInt64,System.Boolean,System.Int32,System.Threading.CancellationToken)~System.Collections.Generic.IEnumerable{Microsoft.Diagnostics.Runtime.GCRootPath}")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.GCRoot.EnumerateGCRoots(System.UInt64,System.Boolean,System.Threading.CancellationToken)~System.Collections.Generic.IEnumerable{Microsoft.Diagnostics.Runtime.GCRootPath}")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.GCRoot.EnumerateGCRoots(System.UInt64,System.Threading.CancellationToken)~System.Collections.Generic.IEnumerable{Microsoft.Diagnostics.Runtime.GCRootPath}")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.DataTarget.LoadDump(System.String,Microsoft.Diagnostics.Runtime.CacheOptions)~Microsoft.Diagnostics.Runtime.DataTarget")]
[assembly: SuppressMessage("ApiDesign", "RS0026:Do not add multiple public overloads with optional parameters", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.DataTarget.LoadDump(System.String,System.IO.Stream,Microsoft.Diagnostics.Runtime.CacheOptions,System.Boolean)~Microsoft.Diagnostics.Runtime.DataTarget")]
[assembly: SuppressMessage("ApiDesign", "RS0027:Public API with optional parameter(s) should have the most parameters amongst its public overloads.", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.Utilities.PEImage.#ctor(System.IO.Stream,System.Boolean)")]
[assembly: SuppressMessage("ApiDesign", "RS0027:Public API with optional parameter(s) should have the most parameters amongst its public overloads.", Justification = "Backwards compatability", Scope = "member", Target = "~M:Microsoft.Diagnostics.Runtime.Utilities.ResourceEntry.GetData``1(System.Int32)~``0")]
