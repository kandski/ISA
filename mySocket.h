//
// Created by kandski on 10/15/17.
//

#ifndef ISA_MYSOCKET_H
#define ISA_MYSOCKET_H

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

using namespace std;

class mySocket {
public:
    /**
     *
     */
    mySocket();
    /**
     *
     */
    ~mySocket();
    /**
     * connect method does initialize connection to the server
     * @param port - number of port on the server
     * @param server - server address or name
     * @return 0 if everthing passes, else return specified error
     */
    int connect(long port, string server);
    /**
     * Method hostname_to_ip does translate hostname to the ip address
     * @param hostname
     */
    void hostname_to_ip(const string &hostname);
    /**
     * Method sends given message through unsecured socket
     * @param msg - message to send
     * @param param - if there should be any parameter with command, e.g. number of message, it is stored in this variable
     */
    void sendMsg(string msg, string param = "");
    /**
     * Method does send command to the server to login with username and password
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
     * @param delim -
     * @return message from server or specified error
     */
    string readData(string delim = "\r\n");
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


private:
    uint16_t port;
    string server;
    int sockfd;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;

    /**
    * Method to handle dot-stuffed (duplication of dots)
    * @param data - message with duplicated dots
    * @return message without duplicate dots
    */
    string removeDotStuffed(string data);
};


#endif //ISA_MYSOCKET_H
