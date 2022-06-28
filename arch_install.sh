
sudo pacman -S astyle cmake gcc ninja python-pytest python-pytest-xdist unzip libxslt doxygen graphviz python-yaml python-pip git openssl
pip3 install cryptography
pip3 install argon2-cffi
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja .. -DBUILD_SHARED_LIBS=ON
ninja
sudo ninja install