sudo dnf install astyle cmake gcc-c++ ninja-build openssl-devel python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml python3-pip git
mkdir -p ~/.pqcryptvenv
python3 -m venv ~/.pqcryptvenv
source ~/.pqcryptvenv/bin/activate
pip3 install --require-virtualenv -r requirements.txt
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja .. -DBUILD_SHARED_LIBS=ON
ninja
sudo ninja install
deactivate
