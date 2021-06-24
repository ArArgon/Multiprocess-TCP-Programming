# UESTC Computer Networking Experiment 4: Multiprocess TCP Programming

Copyright: 张翔(Template), Argon(Code completion & refactoring)

**Disclaimer**: **DO NOT** copy these code. You may face serious consequences for plagiarism. This project is for **study purpose** only!

---

## Features

1. Rewrite some disorganized parts of the given template.
2. Intensive and detailed debugging verbose into `stderr`.
    - All data are shown in Base64.
    - Received data sizes are displayed.
    - Key procedures are put on view.
3. CMake support, empowering further transplant & development.
    - `C99` standard;
    - Minimum cmake version: `3.10`
    
## Building & Running

0. Before you building this project, make sure you have any C compiler(`gcc`, `clang`, `icc`, ...), `make` and `cmake` installed.
1. Build the project
   
   ```shell
   cmake CMakeLists.txt
   make
   ```
   If you would like to display debug output, all you have to do is uncomment this line in `CMakeList.txt`:
   ```cmake
   # add_definitions(-DDEBUG)
   
   # uncomment:
   add_definitions(-DDEBUG)
   ```

2. Copy test data into current directory:
   
   ```shell
   cp ./TestData/* ./
   ```
   
3. Run the server:

   ```shell
   ./NE4Server 127.0.0.1 9090
   ```

4. Run the Client:

   ```shell
   ./NE4Client 127.0.0.1 9090 6
   ```