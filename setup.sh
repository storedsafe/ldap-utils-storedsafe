#!/bin/bash
if ! [ -f "tokenhandler.py" ]; then
    echo "[setup] Downloading StoredSafe tokenhandler..."
    git clone https://github.com/storedsafe/tokenhandler.git tokenhandler-git
    mv tokenhandler-git/tokenhandler.py ./tokenhandler.py
    rm -rf tokenhandler-git
fi

if ! [ -d "venv" ]; then
	echo "[setup] Setting up venv..."
	python3 -m venv venv
fi

echo "[setup] Installing dependencies..."
source venv/bin/activate
python3 -m pip install -r requirements.txt
