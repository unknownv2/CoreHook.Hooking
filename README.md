# CoreHook Windows Hooking Module

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/unknownv2/CoreHook.Hooking/blob/master/LICENSE)
[![Releases](https://img.shields.io/github/release/unknownv2/CoreHook.Hooking.svg?colorB=33b2e0)](https://github.com/unknownv2/CoreHook.Hooking/releases)
[![Build status](https://ci.appveyor.com/api/projects/status/872ts255gwk9hyjp/branch/master?svg=true)](https://ci.appveyor.com/project/unknownv2/corehook-hooking/branch/master)


For [CoreHook](https://github.com/unknownv2/CoreHook), the [Microsoft Detours](https://github.com/Microsoft/Detours) package serves as a good binary hooking module since it supports x86, x86_64, ARM, and ARM64, while [EasyHook](https://github.com/EasyHook/EasyHook) only supports x86 and x86_64. Since .NET Core supports the two ARM architectures, we can implement the necessary changes to support those architectures for CoreHook.

# Supported Platforms

`X86, X64, and ARM`. If you have a *Windows on ARM* device to test `ARM64` with, pull requests and contributions are all welcome!

# Binary Releases 
 You can download the pre-built Windows binaries [here](https://github.com/unknownv2/CoreHook.Hooking/releases).
 
 For `x86, x64`, extract the zip corresponding to your target architecture, then place the `corehook32.dll` and/or `corehook64.dll` in the build output directory of your program.
 
 For `ARM, ARM64`,  extract the zip corresponding to your target architecture, then place the `corehook32.dll` and/or `corehook64.dll` in the output directory of your published program, created either from using the [Publishing Script](https://github.com/unknownv2/CoreHook#publishing-script) or the `dotnet publish` command.

# Building

Building the DLL requires Visual Studio and that can be accomplished by using `cmake` or the tools that come with `Visual Studio`. This can be the `Visual Studio IDE` or `msbuild` within the `Developer Command Prompt`.

## CMake 

You can build the library using CMake by running [`build.cmd`](build.cmd), which builds the library for the `x86` and `x64` architectures. This also gives you the option to generate and build the library with an older version of `Visual Studio` such as `VS 2015` or `VS 2013`.

## Visual Studio

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


# Usage

* For X86, the output directory is `bin/x86` and the output file is `corehook32.dll`.
* For X64, the output directory is `bin/x64` and the output file is `corehook64.dll`.
* For ARM, the output directory is `bin/ARM` and the output file is `corehook32.dll`.
* For ARM64, the output directory is `bin/ARM64` and the output file is `corehook64.dll`.

Copy the desired file for your target architecture to the output directory of the program that uses [CoreHook](https://github.com/unknownv2/CoreHook/).


# Credits

The hooking module is mostly based on the [EasyHook](https://github.com/EasyHook/EasyHook/blob/master/LICENSE) native module and the [Microsoft Detours](https://github.com/Microsoft/Detours/blob/master/LICENSE.md) library and this library wouldn't be possible without them. They are both MIT-licensed.

