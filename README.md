# CoreHook Windows Hooking Module

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/unknownv2/CoreHook.Hooking/blob/master/LICENSE)
[![Build status](https://ci.appveyor.com/api/projects/status/872ts255gwk9hyjp/branch/master?svg=true)](https://ci.appveyor.com/project/unknownv2/corehook-hooking/branch/master)


For [CoreHook](https://github.com/unknownv2/CoreHook), the [Microsoft Detours](https://github.com/Microsoft/Detours) package serves as a good binary hooking module since it supports x86, x86_64, ARM, and ARM64, while [EasyHook](https://github.com/EasyHook/EasyHook) only supports x86 and x86_64. Since .NET Core supports the two ARM architectures, we can implement the necessary changes to support those architectures for CoreHook.

## Supported Platforms

`X86, X64, and ARM`. If you have a *Windows on ARM* device to test `ARM64` with, pull requests and contributions are all welcome!

## Building

Building the DLL requires Visual Studio and there are two options: You can build the DLL by using the `Visual Studio IDE` or `msbuild` within the `Developer Command Prompt`, or `nmake` (it has been tested with `Visual Studio 2017` only). 

### Visual Studio
You can find the Visual Studio solution inside [the msvc folder](/msvc). You can choose a configuration (**Debug|Release**) and a platform (**X86|X64|ARM|ARM64**) and build. 

An example for building the X64 `corehook64.dll` in the Release configuration:

```
msbuild msvc/corehook/detours.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild msvc/corehook/corehook.vcxproj /p:Configuration=Release /p:Platform=x64
```

To build the entire solution (which also builds the library tests), you can run:

```
nuget restore msvc/corehook.sln
msbuild msvc/corehook.sln /p:Configuration=Release /p:Platform=x64
```


### NMAKE 

You can find the build environments for your Visual Studio installation normally at `C:\Program Files (x86)\Microsoft Visual Studio\2017\[ProductType]\VC\Auxiliary\Build`, where `[ProductType]` is your version of Visual Studio: **(Community, Professional, or Enterprise)**.

### X86
* Start the `vcvars32.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:
 ```
 nmake DETOURS_TARGET_PROCESSOR=X86
 ```
### X64 
* For X64, start the `vcvars64.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:

 ```
 nmake DETOURS_TARGET_PROCESSOR=X64
 ```

### ARM

* For ARM, start the `vcvarsx86_arm.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:

 ```
 nmake DETOURS_TARGET_PROCESSOR=ARM
 ```

 ### ARM64 (Unsupported, for future reference)
* For ARM64, start the `vcvarsamd64_arm64.bat`. Then `cd` to the `CoreHook.Hooking` directory, and run:
 ```
 nmake DETOURS_TARGET_PROCESSOR=ARM64
 ```

### Binary Releases 
 You can also download the pre-built Windows binaries [here](https://github.com/unknownv2/CoreHook.Hooking/releases).
 
 For `x86, x64`, extract the zip corresponding to your target architecture, then place the `corehook32.dll` and/or `corehook64.dll` in the build output directory of your program.
 
 For `ARM, ARM64`,  extract the zip corresponding to your target architecture, then place the `corehook32.dll` and/or `corehook64.dll` in the output directory of your published program, created either from using the [Publishing Script](https://github.com/unknownv2/CoreHook#publishing-script) or the `dotnet publish` command.

## Usage

* For X86, the output directory is `bin.X86` and the output file is `corehook32.dll`.
* For X64, the output directory is `bin.X64` and the output file is `corehook64.dll`.
* For ARM, the output directory is `bin.ARM` and the output file is `corehook32.dll`.
* For ARM64, the output directory is `bin.ARM64` and the output file is `corehook64.dll`.

Copy the desired file for your target architecture to the output directory of the program that uses [CoreHook](https://github.com/unknownv2/CoreHook/).


## Credits

The hooking module is mostly based on the [EasyHook](https://github.com/EasyHook/EasyHook/blob/master/LICENSE) native module and the [Microsoft Detours](https://github.com/Microsoft/Detours/blob/master/LICENSE.md) library and this library wouldn't be possible without them. They are both MIT-licensed.

