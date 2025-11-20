<div align="center">

# mem-analyzer

[![C++](https://img.shields.io/badge/C++-17-blue)](https://isocpp.org/)
[![Windows](https://img.shields.io/badge/Windows-10%2B-green)](https://learn.microsoft.com/en-us/windows/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Lightweight Windows memory analysis toolkit**  
Pattern scanning • process attachment • region enumeration • external R/W  
Built for learning and research.


</div>

## Why This Project?

A clean, well-documented playground for exploring the Windows Process API (`ReadProcessMemory`, `VirtualQueryEx`, `CreateToolhelp32Snapshot`, etc.).  
Features anchor-optimized scanning (4–5× faster than naïve implementations) and `.ini`-driven profiles so experiments are repeatable.


## Features

| Feature                        | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| Process attachment            | Auto-lookup by executable name, `PROCESS_ALL_ACCESS`                        |
| Module base resolution        | `MODULEENTRY32` → instant base address                                      |
| Templated memory R/W          | Safe `Read<T>()` / `Write<T>()` with bounds checking                         |
| Anchor-optimized pattern scan | Wildcards (`??`), in-process + external modes, huge speed boost             |
| Smart region filtering        | Only scan readable/committed pages → no crashes                             |
| Configurable profiles         | `config.ini` for patterns, regions, masks — no recompiling required        |

## Quick Start (5 minutes)

```cpp
// Find notepad.exe and scan for a common function prologue
auto pid   = GetProcessID("notepad.exe");
auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
auto base  = GetBaseAddress(pid, "notepad.exe");

SignatureScanner scanner(handle, base, base + 0x2000000);
auto result = scanner.scanEx("48 89 5C 24 ?? 57 48 83 EC 20", 0);

std::cout << "Found at: 0x" << std::hex << result << std::endl;
