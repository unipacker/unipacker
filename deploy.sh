#!/usr/bin/env bash
python3 setup.py $DISTS
python3 -m twine upload dist/*