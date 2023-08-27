## Musig2 client

Before using this client, make sure you have the [server](https://github.com/ssantos21/blinded-musig-sgx-server) running.

```
$ git clone https://github.com/ssantos21/blinded-musig2-client.git
$ cd blinded-musig2-client
$ cd build
$ cmake ..
$ make
$ ./client create-aggregated-public-key
{"aggregate_xonly_pubkey":"<pub-key>"}
$ ./client sign -a <pub-key> -m Teste
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