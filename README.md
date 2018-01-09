# POP3 client with TLS authentication

## Included files:
    argparser.cpp
    argparser.h
    main.cpp
    Makefile
    mySecuredSocket.cpp
    mySecuredSocket.h
    mySocket.cpp
    mySocket.h

## Specification of arguments - help:
```
    ------  ------  ------  ------  ------
    Usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>
    Arguments order is arbitrary.
    ------  ------  ------  ------  ------
    -p number of port on remote server
    -T (TLS) connect to remote server securely
    -S (STARTTLS) connect to remote server unsecured and initiate secure communication
    -c name of certification file
    -C name of certification directory
    -d delete all messages from server after download
    -n download and save just new messages
    -a name of file with authentication data --required
    -o name of folder where messages will be saved --required
    ------  ------  ------  ------  ------
```
## Known disadvantages of implementation:

- Whole message have to be downloaded to retrieve Message-Id on which is based save and creation of files.
- When non-existing directory is given to client, and no message was downloaded from server, directory will be created either.  

#### Example of using on IPv6 address of seznam.cz POP3 server with TLS encryption
```./popcl 2a02:598:a::78:46 -o test_dir_for_email -a auth.conf  -T```

#### Example of using on IPv6 address of seznam.cz POP3 server with STARTTLS encryption
```./popcl 2a02:598:a::78:46 -o test_dir_for_email -a auth.conf  -S```

#### Example of using on IPv4 address of sezanm.cz POP3 server without any encryption
```./popcl 77.75.78.46 -o test_dir_for_email -a auth.conf ```

#### Example of using on IPv4 address of sezanm.cz POP3 server with TLS encryption and specified folder with certificates
```./popcl 77.75.78.46 -o test_dir_for_email -a auth.conf -T -C etc/certs/```


