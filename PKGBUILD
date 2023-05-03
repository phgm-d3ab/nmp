pkgname=libnmp-git
pkgver=GIT_LATEST
pkgrel=1
pkgdesc="Simple networking protocol written in C"
arch=('x86_64')
url="https://github.com/phgm-d3ab/nmp"
license=('MIT')
makedepends=('git' 'cmake') 
depends=('glibc' 'linux>=6.0' 'openssl>=3.0' 'liburing>=2.3')
provides=("${pkgname%-git}")
conflicts=("${pkgname%-git}")

pkgver() {
	cd "$srcdir/nmp"
	printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

prepare() {
	git clone https://github.com/phgm-d3ab/nmp.git
	echo "add_compile_definitions(NDEBUG)" >> "$srcdir/nmp/CMakeLists.txt"
	
	export NMP_SHARED=1
	cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=/usr "$srcdir/nmp/CMakeLists.txt"
}

build() {
	make
}

check() {
    make test
}

package() {
	make DESTDIR="$pkgdir/" install
}
