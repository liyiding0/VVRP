opkg install python3-xml python3-psutil python3-ctypes python3-multiprocessing python3-unittest python3-urllib python3 python3-pip python3-logging python3-unittest python3-uuid ca-bundle ca-certificates python3-openssl

python3 -m pip install -e .

python3 -m pip install prompt_toolkit wcwidth
如果下载超时，就加大超时时间：
python3 -m pip install prompt_toolkit wcwidth --timeout 120 --retries 10 --progress-bar off