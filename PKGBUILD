pkgname=zara-re-platform
pkgver=1.0.0
pkgrel=1
pkgdesc="Native reverse engineering framework for binary analysis, decompilation, debugging, and automation"
arch=('x86_64' 'aarch64')
url="https://github.com/regaan/Zara"
license=('AGPL3')
depends=('qt6-base' 'sqlite' 'curl' 'capstone' 'python')
makedepends=('cmake' 'ninja' 'pkgconf')
options=('!lto')
source=()
sha256sums=()

build() {
  local builddir="$srcdir/build"

  cmake -S "$startdir" -B "$builddir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=OFF \
    -DZARA_BUILD_CLI=ON \
    -DZARA_BUILD_DESKTOP_QT=ON

  cmake --build "$builddir"
}

package() {
  local builddir="$srcdir/build"
  DESTDIR="$pkgdir" cmake --install "$builddir"
}
