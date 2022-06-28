sudo dnf install astyle cmake gcc-c++ ninja-build openssl-devel python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml python3-pip git
pip3 install cryptography
pip3 install argon2-cffi
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja .. -DBUILD_SHARED_LIBS=ON
ninja
sudo ninja install