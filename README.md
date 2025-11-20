<div align="center">

# mem-analyzer

![Pinned](https://img.shields.io/badge/Pinned-on%20Profile-blue)
[![C++](https://img.shields.io/badge/C++-17-blue)](https://isocpp.org/) [![WinAPI](https://img.shields.io/badge/WinAPI-10.0-green)](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Lightweight Windows Memory Analysis Toolkit**  
*Pattern scanning, process attachment, memory regions, dynamic offset resolution—for educational and research use only.*



</div>

## Why This Tool?

mem-analyzer simplifies low-level Windows process analysis for developers, researchers, and students. Built with performance in mind (e.g., anchor-optimized scanning for 4× speed gains), it's a clean starting point for exploring WinAPI internals like `ReadProcessMemory` and `VirtualQueryEx`. I created it to practice documenting complex code—full API guides in Doxygen + Markdown included.

## Features

| Feature | Description |
|---------|-------------|
| **Process Attachment** | Auto-find PID by executable name with `PROCESS_ALL_ACCESS`. |
| **Module Base Resolution** | Retrieve base address via `MODULEENTRY32` for targeted scans. |
| **Memory R/W** | Templated `Read<T>()` / `Write<T>()` wrappers for safe access. |
| **Pattern Scanner** | Anchor-optimized with `??` wildcards; supports in-process and external modes. |
| **Region Query** | Filter readable/committed pages using `VirtualQueryEx` to avoid crashes. |
| **Configurable Profiles** | `.ini`-driven scan regions, patterns, and masks for repeatable testing. |

## Installation

### Prerequisites
- Windows 10+ (x64)
- Visual Studio 2022 (or CMake 3.20+)
- Link `psapi.lib` for process queries

### Build from Source
```bash
# Clone repo
git clone https://github.com/kopyk/mem-analyzer.git
cd mem-analyzer

# Visual Studio
devenv mem-analyzer.sln /build Release

# Or CMake
mkdir build && cd build
cmake .. -A x64
cmake --build . --config Release

```

##  Quick Start
// examples/simple_scan.cpp
#include "include/Memory.h"
#include "include/SignatureScanner.h"
#include <iostream>

int main() {
    // Find and attach to process
    ProcessId = GetProcessID("notepad.exe");
    if (!ProcessId) {
        std::cout << "Process not found!" << std::endl;
        return 1;
    }
    ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    ModuleBase = GetBaseAddress(ProcessId, "notepad.exe");

    // Scan for pattern
    SignatureScanner scanner(ProcessHandle, ModuleBase, ModuleBase + 0x1000000);
    auto addr = scanner.scanEx("48 89 5C 24 ?? 57 48 83 EC 20", 0);  // Example: Function prologue with wildcard

    std::cout << (addr ? "Found at: 0x" << std::hex << addr : "Pattern not found.") << std::endl;
    return 0;
}
