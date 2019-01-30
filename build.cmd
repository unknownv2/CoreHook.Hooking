mkdir build32-vs2017
mkdir build64-vs2017
cd build32-vs2017
cmake -G "Visual Studio 15 2017" ../
cd ../
cd build64-vs2017
cmake -G "Visual Studio 15 2017 Win64" ../
cd ../
cmake --build build32-vs2017 --config Debug
cmake --build build32-vs2017 --config Release
cmake --build build64-vs2017 --config Debug
cmake --build build64-vs2017 --config Release