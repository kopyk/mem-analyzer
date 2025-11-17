# mem-analyzer

**A lightweight Windows internal memory analysis toolkit**  
*Read, write, scan signatures, and resolve dynamic offsets in 64-bit processes.*

>This library is intended for **educational** purposes only.  


---

## Features

| Capability | Description |
|------------|-------------|
| **Process attachment** | Open `HANDLE` with `PROCESS_ALL_ACCESS` (or minimal rights) |
| **Memory R/W** | `ReadProcessMemory` / `WriteProcessMemory` wrappers |
| **Pattern scanning** | IDA-style signature scanner (`??` wildcards) |
| **Dynamic offset resolver** | Load offsets from `Offsets.h` or external JSON |
| **Configurable** | `config.ini` drives target PID, module name, scan region |

---

## Quick Start

```bash
git clone https://github.com/dontkopy/mem-analyzer.git
cd mem-analyzer
# Build with Visual Studio 2022 (x64 Release)
devenv mem-analyzer.sln /build Release
