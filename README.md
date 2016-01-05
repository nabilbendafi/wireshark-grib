wireshark-grib
==============

GRIB dissector plugin for wireshark. Is nothing more then wrapper around [ECMWF GRIB-API](https://software.ecmwf.int/wiki/display/GRIB/Home)

Build and install
-----------------

1. Create a build directory and move to it, for example "mkdir build; cd build"
2. Generate Makefile "cmake .."
3. Now build the plugin "make"
4. And the plugin should be built as "grib.so", just copy it to the plugins folder "cp grib.so ~/.wireshark/plugins/"
 
You need the wireshark headers, the glib-2.0 headers, the libcrypto headers (install openssl headers) and of course the gcc C/C++ compiler.

For Windows build:

1. Create a build directory and move to it, for example "mkdir build; cd build"
2. Tweak mingw32-windows.toolchain according to your needs.
3. Generate Makefile "cmake -DCMAKE_TOOLCHAIN_FILE=../mingw32-windows.toolchain .." (set WIRESHARK_INCLUDE_DIRS, GCRYPT_INCLUDE_DIR variables if needed)
4. Now build the plugin "make"
5. And the plugin should be built as "grib.dll", just copy it to the plugins folder "C:\Program Files\Wireshark\Plugins\'version'\grib.dll"

Windows builds are not fully tested yet.

Usage
-----

After plugin installation, just launch Wireshark and select your GRIB port number (a.k.a TCP port on which you reveive raw GRIB data)
