# Final Project Submission

Please see the `README.pdf` for the same information but with screenshots instead of text.

## Building the Executable

1. Within this repository enter each of the `Auth-Server`, `Client-Server` and `Chat-Server` directories and run `make`.
    ```
    cd Auth-Server && make && cd ..
    cd Client-Server && make && cd ..
    cd Chat-Server && make && cd ..
    ```
2. Run `make` from the repository root directory.
    ```
    make
    ```
3. Kill any running instances of the server if they are still persisting.
    ```
    pkill -f auth-server && pkill -f chat-server && pkill -f client-server
    ```

    > [!NOTE]
    > Similar Functionality is contained in the `run_test.sh` program but this will run all the processes from the same terminal.

## (Optional) Generating a new Certificate
As we are communicating over `localhost` the provided certificate is fine for demonstration purposes. However, you can regenerate one using the command below.

> [!NOTE]
> The certificate and key should be placed in the `./Certs` directory and named `as-c.pem` and `as-k.pem` respectively. You can modify the `./Auth-Server/auth-var.h` file to change where the keys are read from.

1. Run the following command
    ```
    openssl req -x509 -newkey rsa:4096 -keyout as-k.pem -out as-c.pem -nodes
    ```
    * Fill out information as desired, set common name to hostname/ip of the system we are using to resolve/connect to the server


You can generate a new chat server key (symmetric) by compiling and running the `./Util/keygen` program.
1. Enter into the `./Util` directory and run make
    ```
    cd ./Util && make
    ```
2. Run the `keygen` program
    ```
    ./keygen
    ```
3. Copy the resulting key to a file named `./Certs/chat_server_key.bin`

## Running the Servers and Chat Client
1. Open four terminal Windows (You can also put the servers in the background with `&`, or use tmux/screen etc)
2. Start the `auth-server` binary, and the `chat-server` binary each in their own window (Or place them in the background with `&`)
3. Start `client-server` program, this will prompt you to login or register. Select `r` for register.
4. Login with the username and password you registered with.
5. Repeat steps 3 and 4 in another terminal.
6. Send messages between the clients.