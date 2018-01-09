//
// Created by Rastislav Kanda on 12.10.17.
//

#ifndef PROJEKT_ARGPARSER_H
#define PROJEKT_ARGPARSER_H

#include <iostream>
#include <unistd.h>
#include <string>
#include <regex>
#include <sstream>
#include <fstream>
#include <netdb.h>

#include <openssl/ssl.h>


using namespace std;

class parser {
public:
    /**
     * Constructor of parser class
     * @param argcount - value from argc
     * @param argvector - value from argv array
     */
    parser(int argcount, char** argvector);

    int argc;
    char** argv;

    /**
     * Method extract authentification data from given file
     */
    void getAuthData();
    /**
     * Method returns value from private variable of class
     * @return number of port
     */
    long returnPort();
    /**
     * Method returns value from private variable of class
     * @return server address
     */
    string returnServer();
    /**
     * Method returns value from private variable of class
     * @return username value
     */
    string getUsername();
    /**
     * Method returns value from private variable of class
     * @return password value
     */
    string getPassword();
    /**
     * Method returns value from private variable of class
     * @return path to folder to save messages
     */
    string getOutdir();
    /**
     * Method returns value from private variable of class
     * @return path to certification folder
     */
    string getCertdir();
    /**
     * Method returns value from private variable of class
     * @return path to file with certificate
     */
    string getCertfile();
    /**
     * Method returns value from private variable of class
     * @return true if TLS communication should be initialized
     */
    bool secureStart();
    /**
     * Method returns value from private variable of class
     * @return true if messages should be deleted from server
     */
    bool do_delete();
    /**
     * Method returns value from private variable of class
     * @return true if STARTTLS communication should be enabled
     */
    bool do_secure();
    /**
     * Method returns value from private variable of class
     * @return true if client should operate just with new messages
     */
    bool is_just_new_msgs();


private:
    /**
     * Main method which parses arguments from standard input and stores them into class variables
     */
    void parse_arg();
    char *const *args;
    std::string server_name;
    std::string server_addr;
    long port;       //-p
    std::string certfile;   //-c
    std::string certaddr;   //-C
    std::string out_dir;    //-o
    std::string auth_file;  //-a
    bool to_delete;         //-d
    bool to_secure;         //-S
    bool secure_start;      //-T
    bool just_new_msg;      //-n
    string *authdata;
    string username;
    string password;
    /**
     * Method which checks if server address is in right format
     * @param hostname - <server> argument value
     * @return true if address is valid
     */
    bool hostname_to_ip(const string &hostname);

    void showHelp();
};


#endif //PROJEKT_ARGPARSER_H
