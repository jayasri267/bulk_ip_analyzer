#!/bin/bash
PYTHONPATH=$(pwd) streamlit run frontend/main.py --server.headless false
