# Xamarin

### Reverse

Extract the DLLs then use ILSpy:

#### Step 1:

* Mac) Install Visual Studio for Mac ([http://visualstudio.microsoft.com/vs/mac/](http://visualstudio.microsoft.com/vs/mac/)). It has MonoDevelop, all .NET tools, a full IDE, etc...
* Windows) Install Visual Studio or any other way to get the "dotnet" command line tool.
* Linux) Get the "dotnet" command line tool.

#### Step 2:

Go to a Terminal prompt and type `dotnet tool install ilspycmd -g` to install the official ilspy command line version.

Global tools are installed in the following directories by default when you specify the `-g` or `--global` option:

| OS          | Path                          |
| ----------- | ----------------------------- |
| Linux/macOS | `$HOME/.dotnet/tools`         |
| Windows     | `%USERPROFILE%\.dotnet\tools` |

#### Step 3:

Read usage instructions here: [https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.Decompiler.Console](https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.Decompiler.Console). It is very simple. Most of the time you just run it with `ilspycmd -p -o <folder> <dll file>` to decompile to an output folder and make a buildable project file (that is what `-p` does).

Source: [https://github.com/aerror2/ILSpy-For-MacOSX/issues/6](https://github.com/aerror2/ILSpy-For-MacOSX/issues/6)

References:

- [Decompressing Xamarin DLLs](https://www.x41-dsec.de/security/news/working/research/2020/09/22/xamarin-dll-decompression/)

