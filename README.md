# Debugger Detection Tool

This tool uses various debugging detection techniques to identify if a debugger is present on a Windows operating system. The code employs both standard Windows API functions and various techniques to check for the presence of a debugger in the application.

## Features

1. **IsDebuggerPresent**: Uses the `IsDebuggerPresent` Windows API function for basic debugger detection.
2. **IsDebuggerPresent2**: Checks the `BeingDebugged` flag in the Process Environment Block (PEB) to detect if a debugger is present.
3. **IsDebuggerPresent3**: Checks the `NtGlobalFlag` in the PEB to determine if a debugger is present by looking for specific heap flags.
4. **NtQIPDebuggerCheck**: Uses the `NtQueryInformationProcess` API function to query various debugger-related information such as the debug port and debug object handle.
5. **HardwareBpCheck**: Detects hardware-based breakpoints by examining the debug registers.
6. **BlackListedProcessesCheck**: Checks for the presence of blacklisted debugging tools by enumerating running processes.
7. **TimeTickCheck1**: Uses `GetTickCount64` to measure the time difference and check for unusual delays which might indicate a debugger.
8. **TimeTickCheck2**: Uses `QueryPerformanceCounter` to measure the time difference with high precision and check for unusual delays.
9. **DebugBreakCheck**: Calls `DebugBreak` and handles the exception to determine if a debugger is present.
10. **OutputDebugStringCheck**: Uses `OutputDebugStringW` to check if the debug string is being intercepted.

## How It Works

The tool runs a series of checks to detect the presence of a debugger:

1. **IsDebuggerPresent**: Checks if the process is being debugged using the built-in Windows API function.
2. **IsDebuggerPresent2**: Checks the `BeingDebugged` flag in the PEB.
3. **IsDebuggerPresent3**: Checks the `NtGlobalFlag` in the PEB for specific flags indicating a debugger.
4. **NtQIPDebuggerCheck**: Queries the debug port and debug object handle using `NtQueryInformationProcess`.
5. **HardwareBpCheck**: Checks if hardware breakpoints are set in the debug registers.
6. **BlackListedProcessesCheck**: Scans for known debugger processes by comparing against a blacklist.
7. **TimeTickCheck1**: Measures elapsed time using `GetTickCount64` and checks for anomalies.
8. **TimeTickCheck2**: Measures high-resolution elapsed time using `QueryPerformanceCounter` and checks for anomalies.
9. **DebugBreakCheck**: Triggers a breakpoint to see if a debugger handles the exception.
10. **OutputDebugStringCheck**: Checks if debug strings are being intercepted by a debugger.

## Usage

1. **Compile the Code**: Compile the provided code using a Windows-compatible C/C++ compiler.
2. **Run the Executable**: Execute the compiled binary. It will run each debugging detection technique and output the results to the console.

## Example Output
```shell
[#] Running IsDebuggerPresent ...
[+] DONE

[#] Running IsDebuggerPresent2 ...
<<!>> IsDebuggerPresent2 Detected A Debugger <<!>>

[#] Running IsDebuggerPresent3 ...
[+] DONE

[#] Running NtQIPDebuggerCheck ...
<<!>> NtQIPDebuggerCheck Detected A Debugger <<!>>

[#] Running HardwareBpCheck ...
[+] DONE

[#] Running BlackListedProcessesCheck ...
<<!>> BlackListedProcessesCheck Detected A Debugger <<!>>

[#] Running TimeTickCheck1 ...
[+] DONE

[#] Running TimeTickCheck2 ...
[+] DONE

[#] Running DebugBreakCheck ...
[+] DONE

[#] Running OutputDebugStringCheck ...
[+] DONE
```

## Dependencies

- **Windows API**: The tool relies on various Windows API functions and structures.
- **NTDLL.DLL**: Used for querying process information.

## License

This tool is provided as-is. Use it at your own risk. The author is not responsible for any damages caused by the use of this tool.

## Contact

For questions or issues, please contact [mansurovraul1@gmail.com].
