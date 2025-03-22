Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class MemoryDumper
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;

    public static void DumpMemory(int processId, string outputFilePath)
    {
        IntPtr processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, processId);

        if (processHandle == IntPtr.Zero)
        {
            throw new Exception("Failed to open process. Check permissions.");
            Environment.Exit(0);
        }

        Process process = Process.GetProcessById(processId);
        using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
        {
            foreach (ProcessModule module in process.Modules)
            {
                byte[] buffer = new byte[module.ModuleMemorySize];
                int bytesRead;
                if (ReadProcessMemory(processHandle, module.BaseAddress, buffer, buffer.Length, out bytesRead) && bytesRead > 0)
                {
                    fs.Write(buffer, 0, bytesRead);
                }
            }
        }

        CloseHandle(processHandle);
    }
}
"@ -Language CSharp

function Dump-Memory {
    param (
        [string]$ProcessName,
        [int]$ProcessID
    )

    $process = $null

    if ($ProcessID) {
        $process = Get-Process -Id $ProcessID -ErrorAction SilentlyContinue
    } elseif ($ProcessName) {
        $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    }

    if (-not $process) {
        Write-Host -ForegroundColor Red "Process Not Found: $ProcessName or ID: $ProcessID"
        return
    }

    $dumpPath = "$env:TEMP\$($process.ProcessName)_$($process.Id).dmp"

    Write-Host -ForegroundColor Green "Dumping memory for process: $($process.ProcessName) (PID: $($process.Id))"
    
    [MemoryDumper]::DumpMemory($process.Id, $dumpPath)

    Write-Host -ForegroundColor Cyan "Memory dump saved to: $dumpPath"
}
