# Charon

Mythic wrapper payload type for in-memory execution of wrapped payloads via PowerShell.

Charon generates a PowerShell one-liner that fileless-loads a .NET stager assembly. The stager downloads the wrapped payload EXE at runtime and executes it in-memory using RunPE (process hollowing).

## How It Works

```
PowerShell One-Liner
  └─> [System.Reflection.Assembly]::Load()  (fileless .NET stager)
        └─> WebClient.DownloadData()         (fetch wrapped EXE)
              └─> RunPE Process Hollowing    (in-memory execution)
```

1. Operator builds a payload (e.g. Kassandra) and hosts the EXE at a URL
2. Operator builds Charon wrapper, providing the download URL
3. Charon stamps the URL into a C# RunPE stager, compiles it, and outputs a PowerShell one-liner
4. On target: paste the one-liner — stager loads fileless, downloads the EXE, and runs it via process hollowing

## Build Parameters

| Parameter | Description | Default |
|---|---|---|
| `download_url` | URL where the wrapped EXE is hosted | *(required)* |
| `spawn_process` | Sacrificial process for hollowing | `C:\Windows\System32\svchost.exe` |

## Supported Wrapped Payloads

- [Kassandra](https://github.com/PatchRequest/Kassandra) (x86_64 Windows)

The wrapped agent must list `"Charon"` in its `wrapped_payloads` field.

## Installation

Add Charon to your Mythic instance:

```bash
./mythic-cli install folder /path/to/Charon
```

Or install from GitHub:

```bash
./mythic-cli install github https://github.com/PatchRequest/Charon
```

## Requirements

- Mythic 3.x
- Mono (`mcs` compiler) — included in the Docker container
- Wrapped payload must be x64 PE (PE32+)
