#!/usr/bin/env bash
# Inspect the existing Linux environment. No installs, activation or model execution.
set -u

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)" || exit 1
case "$project_dir" in
  /mnt/d/*) ;;
  *) printf 'Run this copy from the D-drive workspace (/mnt/d/...).\n' >&2; exit 1 ;;
esac
cd -- "$project_dir" || exit 1
scratch_dir="$(dirname -- "$project_dir")/.scratch/wsl"
mkdir -p -- "$scratch_dir/tmp" "$scratch_dir/cache" || exit 1
export TEMP="$scratch_dir/tmp" TMP="$scratch_dir/tmp" TMPDIR="$scratch_dir/tmp"
export XDG_CACHE_HOME="$scratch_dir/cache" PIP_CACHE_DIR="$scratch_dir/cache/pip"
export TORCH_HOME="$scratch_dir/cache/torch" HF_HOME="$scratch_dir/cache/huggingface"
export PYTHONDONTWRITEBYTECODE=1
report_path="$scratch_dir/environment-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
exec > >(tee "$report_path") 2>&1

printf 'SymbAI-Taint Linux environment check\nUTC: '
date -u +%Y-%m-%dT%H:%M:%SZ
printf 'Project: %s\nScratch: %s\nKernel: ' "$project_dir" "$scratch_dir"
uname -r
printf '\nFilesystem view (does not identify the Windows VHD location):\n'
df -h -- "$project_dir" /

printf '\nCompiler and utility versions:\n'
for tool in gcc g++ make git dot; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s: %s\n' "$tool" "$(command -v "$tool")"
    "$tool" --version 2>&1 | head -n 1
  else
    printf '%s: missing\n' "$tool"
  fi
done

printf '\nExisting Python interpreters (no packages imported or installed):\n'
declare -A seen_python=()
for python_bin in "$(command -v python 2>/dev/null || true)" \
                  "$(command -v python3 2>/dev/null || true)" \
                  /root/miniconda3/envs/*/bin/python /root/anaconda3/envs/*/bin/python; do
  [ -x "$python_bin" ] || continue
  [ -z "${seen_python[$python_bin]+yes}" ] || continue
  seen_python["$python_bin"]=1
  timeout 15 "$python_bin" -B - <<'PYTHON'
import sys
print("Python: {} ({})".format(sys.executable, sys.version.split()[0]))
try:
    from importlib import metadata
except ImportError:
    print("  importlib.metadata unavailable")
else:
    for name in ("angr", "claripy", "pyvex", "torch", "torch-geometric", "pytest"):
        try:
            value = metadata.version(name)
        except metadata.PackageNotFoundError:
            value = "not installed"
        print("  {}: {}".format(name, value))
PYTHON
  status=$?
  [ "$status" -eq 0 ] || printf 'Interpreter inspection failed or timed out: %s (exit %s)\n' "$python_bin" "$status"
done

printf '\nTYGR source locations and model files (limited to this workspace):\n'
for source_dir in "$project_dir/tygr_original" "$project_dir/tygr" \
                  "$(dirname -- "$project_dir")/TYGR" "$(dirname -- "$project_dir")/tygr_original"; do
  if [ -d "$source_dir" ]; then
    printf 'Directory: %s\n' "$source_dir"
    if [ -f "$source_dir/src/methods/glow/preproc.py" ]; then
      printf '  Glow preprocessor: present\n'
    fi
    find "$source_dir" -maxdepth 4 -type f \( -name '*.model' -o -name '*.pt' -o -name '*.pth' \) -print | head -n 30
  else
    printf 'Absent: %s\n' "$source_dir"
  fi
done

printf '\nGPU visibility (optional):\n'
if command -v nvidia-smi >/dev/null 2>&1; then
  timeout 10 nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>&1 || true
else
  printf 'nvidia-smi: unavailable; A/B can run on CPU.\n'
fi
printf '\nInspection complete. No software installed or model loaded.\nReport: %s\n' "$report_path"
