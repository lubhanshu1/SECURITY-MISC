Option Explicit

Dim computer, os, processor
Dim wmi, items, item

Set wmi = GetObject("winmgmts:\\.\root\cimv2")

WScript.Echo "SECURITY-MISC :: Read-Only System Information"
WScript.Echo "=============================================="

Set computer = wmi.ExecQuery("SELECT ComputerSystem, TotalPhysicalMemory FROM Win32_ComputerSystem")

For Each item In computer
    WScript.Echo "Computer: " & item.Name
    WScript.Echo "RAM: " & FormatNumber(item.TotalPhysicalMemory / 1073741824, 2) & " GB"
Next

Set os = wmi.ExecQuery("SELECT Caption, Version, OSArchitecture FROM Win32_OperatingSystem")

For Each item In os
    WScript.Echo "Operating System: " & item.Caption
    WScript.Echo "Version: " & item.Version
    WScript.Echo "Architecture: " & item.OSArchitecture
Next

Set processor = wmi.ExecQuery("SELECT Name FROM Win32_Processor")

For Each item In processor
    WScript.Echo "Processor: " & item.Name
Next

WScript.Echo ""
WScript.Echo "Mode: READ-ONLY"