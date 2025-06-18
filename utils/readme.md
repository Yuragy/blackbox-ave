## Ave ops

### Brief overview

* **`lkm_infect.sh`** – pushes the Ave kernel module into the system and starts ELF-file infection.
  *Note:* `elfin` is a standalone binary that handles ELF infection autonomously through **libinject.so**; `lkm_infect.sh` is a Bash script that achieves the same via system utilities and external commands. Do not confuse the two.
* **`bd_connect.sh`** – connects to the back-door: opens the right ports, “knocks” the remote host with proper TCP flags, builds TLS tunnels, etc.
* **`lkm_remove.sh`** – force-removes the LKM, wipes traces, scrubs logs – a full “farewell” to the installation.
* **`timestamp_decode.sh`** – converts raw timestamps, used to decode time marks.
* **`ave.ko`** – the primary kernel module; this is what you load with `insmod` / `modprobe`.
* **`run.sh`** – prepares and loads **ave.ko**: first sends **SIGPIPE** to the *dmesg* process to flush kernel logs, then (as root) inserts the module with `insmod`. This is the final entry point.

### Typical workflow

1. Drop **ave.ko** into the desired location (default: `scripts/ave.ko`).
2. Run `lkm_infect.sh <elf>` and make sure `inject/libinject.so` is reachable at the correct path.
3. Execute `bd_connect.sh` to test the back-door or establish network interaction.
4. Need an emergency cleanup? Launch `lkm_remove.sh`.
