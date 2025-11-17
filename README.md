# mem-analyzer

![Reverse Engineering](https://img.shields.io/badge/Reverse%20Engineering-Research-blue)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![WinAPI](https://img.shields.io/badge/WinAPI-10.0-green)

**Lightweight Windows Memory Analysis Toolkit**  
*Pattern scanning, process attachment, memory regions, dynamic offset resolution*

> **Educational Use Only**  


---

## Features

| Feature | Description |
|-------|-------------|
| **Process Attachment** | Auto-find PID by executable name |
| **Module Base Resolution** | `GetBaseAddress()` via `MODULEENTRY32` |
| **Memory R/W** | Templated `Read<T>()` / `Write<T>()` |
| **Pattern Scanner** | Anchor-optimized, `??` wildcards, in-process + external |
| **Region Query** | `VirtualQueryEx` → readable, committed pages |
| **Configurable Profiles** | `.ini` driven scan regions & patterns |
| **Structures** | `Vector3`, `Matrix`, `WorldToScreen`, health components |

---







## Quick Start

```cpp
// examples/simple_scan.cpp
#include "include/Memory.h"
#include "include/SignatureScanner.h"

int main() {
    ProcessId = GetProcessID("notepad.exe");
    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    ModuleBase = GetBaseAddress(ProcessId, "notepad.exe");

    SignatureScanner scanner(ProcessHandle, ModuleBase, ModuleBase + 0x1000000);
    auto addr = scanner.scanEx("48 89 5C 24 ?? 57 48 83 EC 20", 0);

    printf("Found at: 0x%llX\n", addr);
}
