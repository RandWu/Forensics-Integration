' === Direct access to Win32_Process data ===
' -------------------------------------------
Set WshShell = WScript.CreateObject("WScript.Shell")
Set locator = CreateObject("WbemScripting.SWbemLocator")
Set service = locator.ConnectServer()
Set processes = service.ExecQuery ("select Name,ProcessId,CommandLine,ParentProcessId,ExecutablePath from Win32_Process")

For Each process in processes
   Return = process.GetOwner(strNameOfUser) 
   wscript.echo process.Name & "," &process.ProcessId & "," & process.ParentProcessId & "," & process.ExecutablePath & "," & chr(39) & process.CommandLine & chr(39)
Next

Set WSHShell = Nothing