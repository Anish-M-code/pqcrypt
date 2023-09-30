source ~/.pqcryptvenv/bin/activate
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export PYTHONPATH=liboqs-python
python3 pqcrypt.py
deactivate
