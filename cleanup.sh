#!/bin/bash
if [ -f "tokenhandler.py" ]; then
    rm tokenhandler.py
fi

if [ -d "venv" ]; then
    rm -rf venv
fi

if [ -d "__pycache__" ]; then
    rm -rf __pycache__
fi
