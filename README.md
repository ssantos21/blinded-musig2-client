## Musig2 client


```
$ git clone https://github.com/ssantos21/musig2_client.git
$ cd musig2_client
$ cd build
$ cmake ..
$ make
$ ./client execute-complete-scheme
```

### VSCode

* Sample `c_cpp_properties.json` configuration (to detect packages fetched by CMake).

```json
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "${workspaceFolder}/build/_deps/sqlite3-src/**"
            ],
            "defines": [],
            "compilerPath": "/usr/bin/gcc",
            "cStandard": "c17",
            "cppStandard": "gnu++17",
            "intelliSenseMode": "linux-gcc-x64"
        },
        {
            "name": "CMake",
            "compileCommands": "${config:cmake.buildDirectory}/compile_commands.json",
            "configurationProvider": "ms-vscode.cmake-tools"
        }
    ],
    "version": 4
}
```