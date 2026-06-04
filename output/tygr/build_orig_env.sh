#!/bin/bash
# Reproduce TYGR's original environment (CPU) so the official pretrained model x64.O0.base.model can be used.
# Versions strictly follow tygr_original/environment.yml (angr/pyvex 9.0.7491 is key to the model's features).
set -e
source /root/miniconda3/etc/profile.d/conda.sh

echo "==== [1] Create conda env tygr-orig (python 3.8.10) ===="
conda create -y -n tygr-orig python=3.8.10

echo "==== [2] Install pytorch 1.8.1 (CPU) ===="
conda run -n tygr-orig pip install torch==1.8.1+cpu torchvision==0.9.1+cpu torchaudio==0.8.1 \
    -f https://download.pytorch.org/whl/torch_stable.html

echo "==== [3] Install the PyG 1.7.0 stack (matching torch-1.8.1+cpu) ===="
conda run -n tygr-orig pip install torch-scatter==2.0.6 torch-sparse==0.6.9 \
    -f https://data.pyg.org/whl/torch-1.8.1+cpu.html
conda run -n tygr-orig pip install torch-geometric==1.7.0

echo "==== [4] Install the angr/pyvex 9.0.7491 family (exact versions the model's features depend on) ===="
conda run -n tygr-orig pip install \
    angr==9.0.7491 archinfo==9.0.7491 claripy==9.0.7491 cle==9.0.7491 pyvex==9.0.7491

echo "==== [5] Remaining dependencies ===="
conda run -n tygr-orig pip install python-louvain==0.15 gitpython python-utils networkx tqdm
# Pitfalls: also pin capstone==4.0.2 and protobuf==3.20.3, plus the rest in req_rest.txt:
#   conda run -n tygr-orig pip install capstone==4.0.2 protobuf==3.20.3 -r output/tygr/req_rest.txt

echo "==== [6] Smoke test: can the official x64.O0.base.model load ===="
cd "$(dirname "$0")/../../tygr_original"
conda run -n tygr-orig python -c "import torch; m=torch.load('model/MODEL_base/x64.O0.base.model', map_location='cpu'); print('official model loaded:', type(m).__name__)"

echo "==== DONE — tygr-orig environment ready ===="
