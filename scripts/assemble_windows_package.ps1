param(
    [Parameter(Mandatory=$true)][string]$QtBuild,
    [Parameter(Mandatory=$true)][string]$SdkBuild,
    [Parameter(Mandatory=$true)][string]$QtRoot,
    [Parameter(Mandatory=$true)][string]$MinGwRoot,
    [Parameter(Mandatory=$true)][string]$QtDocsRoot,
    [Parameter(Mandatory=$true)][string]$StandardLicensesRoot,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Bundle de transporte: source contiene sólo deploymentFiles(Service).
# Las licencias permanecen fuera de source; prepare crea su propio inventario.
# No instala, no firma, no concede autoridad ni modifica configuración del equipo.
try { Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
namespace GateBouncer.Package {
public sealed class Pin : IDisposable {
    internal FileStream Stream;
    internal SafeFileHandle Handle;
    internal Native.Info Identity;
    internal string Path;
    public void Dispose() { if(Stream!=null) Stream.Dispose(); else if(Handle!=null) Handle.Dispose(); }
}
public static class Native {
    [StructLayout(LayoutKind.Sequential)] internal struct Time { public uint Low,High; }
    [StructLayout(LayoutKind.Sequential)] internal struct Info {
        public uint Attributes; public Time Created,Accessed,Written;
        public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string p,uint access,uint share,IntPtr sa,uint mode,uint flags,IntPtr template);
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length,MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
        public uint Length; public IntPtr RootDirectory,ObjectName; public uint Attributes;
        public IntPtr SecurityDescriptor,SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
    [DllImport("ntdll.dll",ExactSpelling=true)]
    static extern int NtCreateFile(out IntPtr handle,uint access,ref ObjectAttributes attributes,out IoStatusBlock status,
        IntPtr allocation,uint fileAttributes,uint share,uint disposition,uint options,IntPtr ea,uint eaLength);
    [DllImport("ntdll.dll",ExactSpelling=true)] static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder s,uint n,uint flags);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string p);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle h);
    static Exception Error(string action,string path) { return new IOException(action+": "+path,new Win32Exception(Marshal.GetLastWin32Error())); }
    public static string Fixed(string path) {
        if(String.IsNullOrEmpty(path)||path.Length<3||!Char.IsLetter(path[0])||path[1]!=':'||path[2]!='\\'||
           path.IndexOf(':',2)>=0||path.IndexOfAny(new[]{'*','?','"','/','\0'})>=0) throw new IOException("Absolute fixed-drive path required: "+path);
        var full=System.IO.Path.GetFullPath(path).TrimEnd('\\');
        if(full.Length==2) full+="\\";
        if(!String.Equals(full,path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)&&
           !String.Equals(full,path,StringComparison.OrdinalIgnoreCase)) throw new IOException("Noncanonical path: "+path);
        if(GetDriveTypeW(full.Substring(0,3))!=3) throw new IOException("Fixed local drive required: "+path);
        return full;
    }
    static void Inspect(Pin pin,bool directory) {
        Info info;
        if(!GetFileInformationByHandle(pin.Handle,out info)) throw Error("Identity unavailable",pin.Path);
        if((info.Attributes&0x400)!=0||((info.Attributes&0x10)!=0)!=directory) throw new IOException("Reparse or wrong shape: "+pin.Path);
        var final=new StringBuilder(32768);
        uint count=GetFinalPathNameByHandleW(pin.Handle,final,32768,0);
        if(count==0||count>=32768||!String.Equals(final.ToString(),"\\\\?\\"+pin.Path,StringComparison.OrdinalIgnoreCase))
            throw new IOException("Path identity mismatch: "+pin.Path);
        pin.Identity=info;
    }
    public static Pin Directory(string path) {
        path=Fixed(path);
        // ShareRead no excluye cambios sólo de atributos; las creaciones usan RootDirectory.
        var pin=new Pin { Path=path,Handle=CreateFileW(path,0x1000A0,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero) };
        try { if(pin.Handle.IsInvalid) throw Error("Directory unavailable",path); Inspect(pin,true); return pin; }
        catch { pin.Dispose(); throw; }
    }
    public static Pin File(string path) {
        path=Fixed(path);
        var pin=new Pin { Path=path,Handle=CreateFileW(path,0x80000080u,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero) };
        try {
            if(pin.Handle.IsInvalid) throw Error("Required file unavailable",path);
            Inspect(pin,false);
            pin.Stream=new FileStream(pin.Handle,FileAccess.Read,65536,false);
            if(pin.Stream.Length>268435456||pin.Stream.Length==0) throw new IOException("File size rejected: "+path);
            return pin;
        } catch { pin.Dispose(); throw; }
    }
    public static Pin CreateOwn(Pin parent,string leaf,bool directory) {
        if(String.IsNullOrEmpty(leaf)||leaf.Length>128||leaf=="."||leaf==".."||leaf.EndsWith(".")||leaf.EndsWith(" ")||
           leaf.Any(c=>c<0x20||c>0x7e||"\\/:*?\"<>|".IndexOf(c)>=0)) throw new IOException("Single ASCII leaf required");
        int pointer=IntPtr.Size;
        if((pointer!=4&&pointer!=8)||Marshal.SizeOf(typeof(UnicodeString))!=(pointer==8?16:8)||
           Marshal.SizeOf(typeof(ObjectAttributes))!=(pointer==8?48:24)||Marshal.SizeOf(typeof(IoStatusBlock))!=pointer*2)
            throw new IOException("Native creation ABI unavailable");
        Current(parent,true);
        IntPtr text=IntPtr.Zero,name=IntPtr.Zero; bool retained=false; SafeFileHandle created=null;
        try {
            parent.Handle.DangerousAddRef(ref retained);
            text=Marshal.StringToHGlobalUni(leaf);
            var unicode=new UnicodeString { Length=checked((ushort)(leaf.Length*2)),MaximumLength=checked((ushort)((leaf.Length+1)*2)),Buffer=text };
            name=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString))); Marshal.StructureToPtr(unicode,name,false);
            var attributes=new ObjectAttributes { Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes)),
                RootDirectory=parent.Handle.DangerousGetHandle(),ObjectName=name,Attributes=0x1040 };
            IoStatusBlock status; IntPtr raw;
            // FILE_CREATE nunca adopta una hoja existente; no resolución del path del padre.
            int result=NtCreateFile(out raw,directory?0x1000A0u:0x12019Fu,ref attributes,out status,IntPtr.Zero,
                directory?0x10u:0x80u,1,2,directory?0x21u:0x200062u,IntPtr.Zero,0);
            if(raw!=IntPtr.Zero&&raw!=new IntPtr(-1)) created=new SafeFileHandle(raw,true);
            if(result!=0||unchecked((int)status.Status.ToInt64())!=0||status.Information.ToUInt64()!=2||created==null||created.IsInvalid)
                throw new IOException("Fresh relative creation failed: "+parent.Path+"\\"+leaf+" (NTSTATUS 0x"+result.ToString("X8")+")",
                    new Win32Exception(unchecked((int)RtlNtStatusToDosError(result))));
            var pin=new Pin { Path=Fixed(System.IO.Path.Combine(parent.Path,leaf)),Handle=created }; created=null;
            try {
                Inspect(pin,directory); Current(parent,true);
                if(!directory) { pin.Stream=new FileStream(pin.Handle,FileAccess.ReadWrite,65536,false);
                    if(pin.Stream.Length!=0) throw new IOException("Created file is not empty: "+pin.Path); }
                return pin;
            } catch { pin.Dispose(); throw; }
        } finally {
            if(created!=null) created.Dispose();
            if(name!=IntPtr.Zero) Marshal.FreeHGlobal(name); if(text!=IntPtr.Zero) Marshal.FreeHGlobal(text);
            if(retained) parent.Handle.DangerousRelease();
        }
    }
    public static void Current(Pin pin,bool directory) {
        var before=pin.Identity; Inspect(pin,directory); var after=pin.Identity;
        if(before.Volume!=after.Volume||before.IndexHigh!=after.IndexHigh||before.IndexLow!=after.IndexLow||
           (!directory&&(before.SizeHigh!=after.SizeHigh||before.SizeLow!=after.SizeLow||
            before.Written.Low!=after.Written.Low||before.Written.High!=after.Written.High)))
            throw new IOException("Retained identity changed: "+pin.Path);
    }
    public static byte[] Read(Pin pin) {
        Current(pin,false); pin.Stream.Position=0;
        var bytes=new byte[checked((int)pin.Stream.Length)]; int at=0;
        while(at<bytes.Length) { int n=pin.Stream.Read(bytes,at,bytes.Length-at); if(n==0) throw new IOException("Short read: "+pin.Path); at+=n; }
        Current(pin,false); return bytes;
    }
    public static byte[] Hash(byte[] bytes) { using(var sha=SHA256.Create()) return sha.ComputeHash(bytes); }
    public static void Write(Pin output,byte[] bytes) {
        if(output.Stream.Length!=0||bytes.Length>268435456) throw new IOException("Output is not fresh: "+output.Path);
        output.Stream.Write(bytes,0,bytes.Length); output.Stream.Flush();
        if(!FlushFileBuffers(output.Handle)) throw Error("Flush failed",output.Path);
        Inspect(output,false); // Nueva identidad sólo después de la escritura propia.
        var observed=Read(output);
        if(!observed.SequenceEqual(bytes)||!Hash(observed).SequenceEqual(Hash(bytes))) throw new IOException("Output readback mismatch: "+output.Path);
    }
    public static void Closed(string root,string[] names) {
        var expected=new HashSet<string>(names,StringComparer.Ordinal);
        var seen=new HashSet<string>(StringComparer.Ordinal);
        var dirs=new[]{"","fonts","plugins","plugins\\platforms"}; int count=0;
        foreach(string dir in dirs) foreach(string item in System.IO.Directory.EnumerateFileSystemEntries(System.IO.Path.Combine(root,dir))) {
            if(++count>64) throw new IOException("Output inventory exceeds its bound");
            string relative=item.Substring(root.Length+1);
            if(dirs.Contains(relative,StringComparer.Ordinal)) continue;
            if(!expected.Contains(relative)||!seen.Add(relative)) throw new IOException("Unexpected output: "+item);
        }
        if(!seen.SetEquals(expected)) throw new IOException("Closed output inventory mismatch");
    }
    public static void Flat(string root,string[] names) {
        var expected=new HashSet<string>(names,StringComparer.Ordinal); var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(string item in System.IO.Directory.EnumerateFileSystemEntries(root)) {
            string name=System.IO.Path.GetFileName(item);
            if(!expected.Contains(name)||!seen.Add(name)||seen.Count>96) throw new IOException("Unexpected bundle entry: "+item);
        }
        if(!seen.SetEquals(expected)) throw new IOException("Bundle entry set mismatch");
    }

}
}
'@
} catch {
    [Console]::Error.WriteLine('Assembly helper unavailable: '+$_.Exception.Message)
    exit 2
}

$pins = [System.Collections.Generic.List[System.IDisposable]]::new()
$directories = [System.Collections.Generic.List[GateBouncer.Package.Pin]]::new()
$files = [System.Collections.Generic.List[GateBouncer.Package.Pin]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$parentPins = [System.Collections.Generic.Dictionary[string,GateBouncer.Package.Pin]]::new([System.StringComparer]::OrdinalIgnoreCase)
function Hold-Parents([string]$path) {
    $path = [GateBouncer.Package.Native]::Fixed($path)
    $chain = [System.Collections.Generic.List[string]]::new()
    for ($p=$path; $p; $p=[System.IO.Path]::GetDirectoryName($p)) {
        if ($chain.Count -ge 64) { throw 'Input parent depth exceeds its bound' }
        $chain.Add($p)
    }
    for ($i=$chain.Count-1; $i -ge 0; --$i) {
        if ($seen.Add($chain[$i])) {
            if ($pins.Count -ge 256) { throw 'Retained object count exceeds its bound' }
            $pin = [GateBouncer.Package.Native]::Directory($chain[$i])
            $pins.Add($pin); $directories.Add($pin)
            $parentPins.Add($chain[$i],$pin)
        }
    }
}
function Hold-File([string]$path) {
    Hold-Parents ([System.IO.Path]::GetDirectoryName($path))
    if ($pins.Count -ge 256) { throw 'Retained object count exceeds its bound' }
    $pin = [GateBouncer.Package.Native]::File($path)
    $pins.Add($pin); $files.Add($pin); return $pin
}
function New-OwnDirectory([string]$path) {
    foreach ($parent in $directories) { [GateBouncer.Package.Native]::Current($parent,$true) }
    if ($pins.Count -ge 256) { throw 'Retained object count exceeds its bound' }
    $parentPath=[System.IO.Path]::GetDirectoryName($path)
    if (!$parentPins.ContainsKey($parentPath)) { throw "Original parent unavailable: $parentPath" }
    $pin = [GateBouncer.Package.Native]::CreateOwn($parentPins[$parentPath],[System.IO.Path]::GetFileName($path),$true)
    $pins.Add($pin); $directories.Add($pin); [void]$seen.Add($path)
    $parentPins.Add($path,$pin)
}
function Write-OwnFile([string]$path,[byte[]]$bytes) {
    foreach ($parent in $directories) { [GateBouncer.Package.Native]::Current($parent,$true) }
    if ($pins.Count -ge 256) { throw 'Retained object count exceeds its bound' }
    $parentPath=[System.IO.Path]::GetDirectoryName($path)
    if (!$parentPins.ContainsKey($parentPath)) { throw "Original parent unavailable: $parentPath" }
    $pin = [GateBouncer.Package.Native]::CreateOwn($parentPins[$parentPath],[System.IO.Path]::GetFileName($path),$false)
    $pins.Add($pin); $files.Add($pin)
    [GateBouncer.Package.Native]::Write($pin,$bytes)
}
try {
    $QtBuild=[GateBouncer.Package.Native]::Fixed($QtBuild)
    $SdkBuild=[GateBouncer.Package.Native]::Fixed($SdkBuild)
    $QtRoot=[GateBouncer.Package.Native]::Fixed($QtRoot)
    $MinGwRoot=[GateBouncer.Package.Native]::Fixed($MinGwRoot)
    $QtDocsRoot=[GateBouncer.Package.Native]::Fixed($QtDocsRoot)
    $StandardLicensesRoot=[GateBouncer.Package.Native]::Fixed($StandardLicensesRoot)
    $OutputRoot=[GateBouncer.Package.Native]::Fixed($OutputRoot)
    $repo=[GateBouncer.Package.Native]::Fixed([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')))
    foreach ($root in @($QtBuild,$SdkBuild,$QtRoot,$MinGwRoot,$QtDocsRoot,$StandardLicensesRoot,$repo)) {
        if ($OutputRoot.Equals($root,[System.StringComparison]::OrdinalIgnoreCase) -or
            $OutputRoot.StartsWith($root+'\',[System.StringComparison]::OrdinalIgnoreCase) -or
            $root.StartsWith($OutputRoot+'\',[System.StringComparison]::OrdinalIgnoreCase)) { throw "Output must be disjoint from inputs: $root" }
        Hold-Parents $root
    }
    Hold-Parents ([System.IO.Path]::GetDirectoryName($OutputRoot))
    $source = [ordered]@{}
    foreach ($name in @('GateBouncerDecisionBootstrap.exe','GateBouncerDecisionStage.dll','GateBouncerGuiStage.dll','GateBouncerAssistant.exe')) { $source[$name]=Join-Path $QtBuild $name }
    foreach ($name in @('GateBouncer.exe','GateBouncerService.exe')) { $source[$name]=Join-Path $SdkBuild $name }
    foreach ($name in @('Qt6Core.dll','Qt6Gui.dll','Qt6Widgets.dll')) { $source[$name]=Join-Path $QtRoot ('bin\'+$name) }
    foreach ($name in @('libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll')) { $source[$name]=Join-Path $MinGwRoot ('bin\'+$name) }
    $source['plugins\platforms\qwindows.dll']=Join-Path $QtRoot 'plugins\platforms\qwindows.dll'
    foreach ($name in @('Inter-Regular.ttf','Inter-Medium.ttf','Inter-SemiBold.ttf')) { $source['fonts\'+$name]=Join-Path $repo ('resources\fonts\'+$name) }
    $source['qt.conf']=$null
    if ($source.Count -ne 17) { throw 'Product inventory must contain exactly 17 files' }
    $notices=[ordered]@{
        'Inter-LICENSE.txt'=Join-Path $repo 'resources\fonts\LICENSE.txt'
        'GCC-COPYING3.txt'=Join-Path $MinGwRoot 'licenses\gcc\COPYING3'
        'GCC-COPYING3-LIB.txt'=Join-Path $MinGwRoot 'licenses\gcc\COPYING3.LIB'
        'GCC-RUNTIME-EXCEPTION.txt'=Join-Path $MinGwRoot 'licenses\gcc\COPYING.RUNTIME'
        'winpthreads-COPYING.txt'=Join-Path $MinGwRoot 'licenses\winpthreads\COPYING'
        'Standard-LGPL-3.0.txt'=Join-Path $StandardLicensesRoot 'LGPL-3.0-only.txt'
        'Standard-GPL-3.0.txt'=Join-Path $StandardLicensesRoot 'GPL-3.0-only.txt'
        'Standard-GPL-2.0.txt'=Join-Path $StandardLicensesRoot 'GPL-2.0-only.txt'
        'Standard-Qt-GPL-exception-1.0.txt'=Join-Path $StandardLicensesRoot 'Qt-GPL-exception-1.0.txt'
        'Qt-qtbase-6.8.2.spdx.json'=Join-Path $QtRoot 'sbom\qtbase-6.8.2.spdx.json'
    }
    # Páginas originales instaladas de Qt 6.8.2: lista cerrada, no glob ni notices fabricados.
    $coreAttributions=@('android-gradle-wrapper','blake2','doubleconversion','easing','sha1','rfc6234','qeventdispatcher-cf','pcre2','pcre2-sljit','md5','md4','kwin','forkfd','extra-cmake-modules','unicode-character-database','tinycbor','tika-mimetypes','siphash','sha3-keccak','sha3-endian','unicode-cldr','zlib')
    $guiAttributions=@('cocoa-platform-plugin','android-native-style','aglfn','freetype-bdf','dejayvu','d3d12memoryallocator','freetype-zlib','freetype-pcf','freetype','harfbuzz-ng','grayraster','icc-srgb-color-profile','iaccessible2','libjpeg','libpng','md4c','opengl-es2-headers','opengl-headers','pixman','webgradients','vulkanmemoryallocator','vulkan-xml-spec','smooth-scaling-algorithm','rhi-miniengine-d3d12-mipmap','xcb-xinput','wintab','xserverhelper')
    foreach ($suffix in $coreAttributions) { $name='qtcore-attribution-'+$suffix+'.html'; $notices[$name]=Join-Path $QtDocsRoot ('qtcore\'+$name) }
    foreach ($suffix in $guiAttributions) { $name='qtgui-attribution-'+$suffix+'.html'; $notices[$name]=Join-Path $QtDocsRoot ('qtgui\'+$name) }
    foreach ($module in @('qtcore','qtgui','qtwidgets')) { $name=$module+'-index.html'; $notices[$name]=Join-Path $QtDocsRoot ($module+'\'+$name) }
    foreach ($name in @('licensing.html','licenses-used-in-qt.html','qtentrypoint.html')) { $notices[$name]=Join-Path $QtDocsRoot ('qtdoc\'+$name) }
    if ($notices.Count -ne 65) { throw 'Notice input set must contain exactly 65 original files' }
    $readers=[ordered]@{}
    foreach ($name in $source.Keys) { if ($null -ne $source[$name]) { $readers[$name]=Hold-File $source[$name] } }
    $noticeReaders=[ordered]@{}
    foreach ($name in $notices.Keys) { $noticeReaders[$name]=Hold-File $notices[$name] }
    # Nada se crea hasta retener todos los inputs requeridos, incluidas licencias reales.
    foreach ($pin in $directories) { [GateBouncer.Package.Native]::Current($pin,$true) }
    New-OwnDirectory $OutputRoot
    $payload=Join-Path $OutputRoot 'source'
    $noticeOutput=Join-Path $OutputRoot 'notices'
    foreach ($path in @($payload,$noticeOutput,(Join-Path $payload 'plugins'),(Join-Path $payload 'plugins\platforms'),(Join-Path $payload 'fonts'))) { New-OwnDirectory $path }
    $names=[string[]]@($source.Keys)
    for ($i=0; $i -lt $names.Length; ++$i) {
        $name=$names[$i]
        [byte[]]$bytes=$null
        if ($name -eq 'qt.conf') { $bytes=[System.Text.Encoding]::ASCII.GetBytes("[Paths]`nPrefix=.`nPlugins=plugins`n") }
        else { $bytes=[GateBouncer.Package.Native]::Read($readers[$name]) }
        Write-OwnFile (Join-Path $payload $name) $bytes
    }
    foreach ($name in $notices.Keys) { Write-OwnFile (Join-Path $noticeOutput $name) ([GateBouncer.Package.Native]::Read($noticeReaders[$name])) }
    $information="Transport bundle only. source contains the closed administrative input set. Administrative preparation computes its own inventory from retained source files. This bundle is not installed or publisher signed and does not establish network protection. notices contains original Qt 6.8.2 module/attribution documentation and qtbase SBOM, supplied standard license texts (not Qt 6.8.2 source), GCC and winpthreads materials, and the Inter license. The HTML files retain their original bytes; external assets and relative navigation are not bundled. These materials do not certify complete redistribution obligations or identify every compiled third-party component.`n"
    Write-OwnFile (Join-Path $OutputRoot 'BUNDLE.txt') ([System.Text.Encoding]::UTF8.GetBytes($information))
    [GateBouncer.Package.Native]::Closed($payload,$names)
    [GateBouncer.Package.Native]::Flat($noticeOutput,[string[]]@($notices.Keys))
    [GateBouncer.Package.Native]::Flat($OutputRoot,[string[]]@('source','notices','BUNDLE.txt'))
    foreach ($pin in $directories) { [GateBouncer.Package.Native]::Current($pin,$true) }
    foreach ($pin in $files) { [GateBouncer.Package.Native]::Current($pin,$false) }
    Write-Output "Bundle assembled: $OutputRoot (source files: 17; not installed)"
    exit 0
} catch {
    # Se preservan archivos propios parciales como evidencia, nunca se borran por path.
    [Console]::Error.WriteLine('Assembly failed: '+$_.Exception.Message)
    exit 2
} finally {
    for ($i=$pins.Count-1; $i -ge 0; --$i) { $pins[$i].Dispose() }
}
