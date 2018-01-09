//
// Created by kandski on 10/17/17.
//

#ifndef ISA_MYSECUREDSOCKET_H
#define ISA_MYSECUREDSOCKET_H


#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <regex>
#include <sstream>
#include <fstream>

#include "argparser.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


using namespace std;

class mySecuredSocket {
public:
    /*
     * Constuctor for class mySecuredSocket
     */
    mySecuredSocket();
    /*
     * Destructor for class mySecuredSocket
     */
    ~mySecuredSocket();
    /**
     * Connect method does initialize connection to the server
     * @param port - number of port on the server
     * @param server - server address or name
     * @param cert_dir - path to the certification directory
     * @param cert_file - path to the certification file
     * @param to_secure - flag to tell if client should use STARTTLS
     * @param secure_start - flag to tell if client should use TLS connection from beggining
     * @return 0 if everthing passes, else return specified error
     */
    int connect(long port, string server, string cert_dir, string cert_file,
                bool to_secure, bool secure_start);
    /**
     * Method hostname_to_ip does translate hostname to the ip address
     * @param hostname
     */
    void hostname_to_ip(const string &hostname);
    /**
     * Method which sends given message securely throughout SSL, function SSL_write() is used for sending
     * @param msg - message to send
     * @param param - if there should be any parameter with command, e.g. number of message, it is stored in this variable
     */
    void sendMsg(string msg, string param = "");
    /**
     * Method sends given message through unsecured socket
     * @param msg - message to send
     * @param param - if there should be any parameter with command, e.g. number of message, it is stored in this variable
     */
    void sendUnsecuredMsg(string msg, string param = "");
    /**
     * Method sends command to the server to login with username and password
     * @param user - username
     * @param pass - password
     * @return 0 if server return OK message, else return specified error
     */
    int login(string user, string pass);
    /**
     * Method sends command to the server to logout and prints final number of downloaded messages
     * @param is_just_new - flag which tells if client should operate only with new messages
     * @return 0 if server return OK message, else return specified error
     */
    int logout(bool is_just_new);
    /**
     * Method downloads whole message from the server
     * @param delim - ending character which stops reading from server
     * @return message from server or return specified error
     */
    string readData(string delim = "\r\n");
    /**
     * Method downloads whole message from the server
     * @param delim - ending character which stops reading from server
     * @return message from server or return specified error
     */
    string readUnsecuredData(string delim = "\r\n");
    /**
     * Method checks if given message contains "+" as first character
     * @param data - message from server
     * @return true if server return OK message, else return specified error
     */
    bool checkOK(string data);
    /**
     * Method which downloads all messages from server and handles deletion of messages
     * @param out_dir - path to directory to save messages
     * @return 0 if server return OK message, else return specified error
     */
    int getAllMsgs(string out_dir, bool, bool);
    /**
     * Method to parse Message-Id from message header
     * @param data - message from server
     * @return message-id of given message
     */
    string getMessageID(string data);

    int number_of_downloaded_messages;
    /**
     * Initialization of SSL connection
     * @param cert_dir
     * @param cert_file
     */
    void mySSLinit(string cert_dir, string cert_file);



private:
    uint16_t port;
    string server;
    int sockfd;

    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;

    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *mySSL;

    /**
     * Method to handle dot-stuffed (duplication of dots)
     * @param data - message with duplicated dots
     * @return message without duplicate dots
     */
    string removeDotStuffed(string data);
};


#endif //ISA_MYSECUREDSOCKET_H
