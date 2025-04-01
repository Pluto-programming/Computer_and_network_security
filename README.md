# Computer_and_network_security
Cybersecurity proposal

## Creating Certificate(s)

In order for the server to run you must edit the `CRT_PATH` and `CRT_KEY` variables in the `Auth-Server/auth-var.h` file.

These variables must contain strings, which are paths to a X.509 certificate and associated private key. We can create a self signed key with:

```sh
$ openssl req -x509 -pubkey -nodes -newkey rsa:4096 -keyout as-k.pem -out as-c.pem 
```

You can test the HTTPS connection with:

```sh
$ openssl s_client -connect <TARGET> -quiet -CAfile <Path-to-CA-File>
```

> [!NOTE]
> Replace `<TARGET>` with the IP:Port of the server we are targeting, and replace `<Path-to-CA-File>` with the filly qualified or relative path.

To test the custom auth we can use telnet.
```
telent <TARGET-IP> <TARGET-PORT>
```
* Then provide input as expected.

## Server
One of the first things we wanted to look into was using the same port for both TLS and Non-TLS connections. To do this we use `recv` to peak at the first few bytes to determine if the packet is one that contains a `Server Hello` message as part of TLS which will start with `0x16 0x03`, or if it is one of our Custom Request packets.

We can see a wireshark capture below showing a Server Hello Message Dump:
![alt text](Images/I1.png)
