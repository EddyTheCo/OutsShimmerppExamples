# Shimmer++. Creating Outputs

The repo produce console application using the Shimmer++ libraries to create the different Outputs on
the ledger of Stardust nodes.

### Build the applications


Clone the repo 
```
git clone https://....
```
Create a build folder, configure the CMake project, build and install
```
mkdir build;cd build
~/Qt/6.6.0/gcc_64/bin/qt-cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=install ../
cmake --build . -t install
```

### Run the applications

Go to the install directory
```
cd install
```

To use a Estervtech node run on the terminal:

```
./bin/app_name https://3216aae.online-server.cloud ef4593558d0c3ed9e3f7a2de766d33093cd72372c800fa47ab5765c43ca006b5 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMkQzS29vV1NSSFVaa3Fyc0hRN2FKbW9wWUhqa1RRZk5zaXJkeW5QWTZHdHRZaURuNEN1IiwianRpIjoiMTY4MjY3NzMwMCIsImlhdCI6MTY4MjY3NzMwMCwiaXNzIjoiMTJEM0tvb1dTUkhVWmtxcnNIUTdhSm1vcFlIamtUUWZOc2lyZHluUFk2R3R0WWlEbjRDdSIsIm5iZiI6MTY4MjY3NzMwMCwic3ViIjoiSE9STkVURVNUSEVSIn0.mKAmVL_eDDz-7yIpxnEai709iGz478lMRKWgPy5FS4s
```
where app_name could be one of:
- basic_output
- NFT_output
- alias_output
- foundry_output
