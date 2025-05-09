# AMSI Knockout
It is one of my first project regarding offensive tools/malware development.

This tool bypasses AMSI permanently based on defined memory pattern 
for a defined group of processes, like `powershell.exe` or `wscript.exe`.

## How does it work?

#### What is AMSI?
At first, let's summarize what AMSI is:

AMSI, or Antimalware Scan Interface, is a security feature integrated into 
Windows that enhances the detection of malware. It provides a standardized 
interface that allows applications and services to send data to be scanned by 
antimalware products. AMSI works in real-time, scanning scripts, macros, and 
other potentially malicious content to identify and block threats before they 
can harm the system. By facilitating better communication between the operating 
system and security software, AMSI helps strengthen the overall security of 
Windows environments.

#### The theory behind
This technique is inspired by [ZeroMemoryEx](https://github.com/ZeroMemoryEx/Amsi-Killer).

1. Memory Patching
In the first step we locate the AMSI library in the process memory, specifically
targeting the `AmsiScanBuffer` function. Because this is the core function
used by AMSI to scan buffers of data for malicious content.

2. Overwriting Function on Process
After identification of the memory location, the tool overwrites the first
few bytes of the `AmsiScanBuffer` function with a sequence of NOPs (no-operation)
or a return operation. With this technique we can effectivley and permanently 
disable the ability of `AMSI` to scan the passed data on the specific process.

3. Security bypassed
After overwriting the first few bytes AMSI is bypassed. Scripts that would
normally be flagged as malicious can now run withoug being detected or 
blocked by `AMSI`. 

#### The theory in action
**TODO:** Add description and images to demonstrate the theory in action!


## Build
To build the tool locally, use the following command on linux:
```bash
$ > GOOS=windows GOARCH=amd64 go build -o ./build/amsi-knockout.exe
```

To build the tool locally, use the following command on windows:
```powershell
PS > go build -o ./build/amsi-knockout.exe
```

## Usage
```powershell
PS > amsi-knockout.exe 

PS > amsi-knockout.exe -processName "powershell.exe"
```


