//
// Created by Rastislav Kanda on 12.10.17.
//

#include "argparser.h"

parser::parser(int argcount, char **argvector) {
    this->server_addr = "";
    this->argc = argcount;
    this->argv = argvector;
    this->out_dir = "";
    this->auth_file = "";
    this->just_new_msg = false;
    this->to_delete = false;
    this->to_secure = false;
    this->certaddr = "";
    this->certfile = "";
    this->port = 110;
    this->server_name = "";
    this->secure_start = false;
    this->parse_arg();
    this->getAuthData();
}

void parser::parse_arg() {
    //pomocne pole na spracovanie argumentov
    auto *arr = new string[argc];
    //pomocna struktura na zistenie platnosti ip adresy
    struct addrinfo hints{}, *res = nullptr;
    int error;
    /*pomocne premmenne na kontrolu kombinacie argumentov*/
    int port_set_flag = 0;
    int server_set_flag = 0;
    int auth_set_flag = 0;
    int out_dir_set_flag = 0;

    memset(&hints, '\0', sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_socktype = SOCK_STREAM;

    //skonkatenovanie pola do stringu
    string tmp;
    for (int j = 1; j < argc; ++j) {
        tmp.append(argv[j]);
        tmp.append(" ");
    }
    //a nasledne rozdelenie do pola
    stringstream ssin(tmp);
    int i = 0;
    while (ssin.good() && i < argc) {
        ssin >> arr[i];
        ++i;
    }

    //hlavny stavovy automat pre kontrolu argumentov
    int c = 0;
    while (c < argc - 1) {
        if (strcmp(arr[c].data(), "-p") == 0) {
            char *endptr;
            this->port = strtol(arr[c + 1].data(), &endptr, 10);
            port_set_flag = 1;
            c++;
        } else if (strcmp(arr[c].data(), "-T") == 0) {
            this->secure_start = true;
        } else if (strcmp(arr[c].data(), "-S") == 0) {
            this->to_secure = true;
        } else if (strcmp(arr[c].data(), "-c") == 0) {
            if (this->to_secure || this->secure_start) {
                this->certfile = arr[c + 1];
                c++;
            } else {
                cerr << "ERROR: Wrong argument combination. " << endl;
                showHelp();
                exit(1);
            }
        } else if (strcmp(arr[c].data(), "-C") == 0) {
            if (this->to_secure || this->secure_start) {
                this->certaddr = arr[c + 1];
                c++;
            } else {
                cerr << "ERROR: Wrong argument combination." << endl;
                showHelp();
                exit(1);
            }
        } else if (strcmp(arr[c].data(), "-d") == 0) {
            this->to_delete = true;
        } else if (strcmp(arr[c].data(), "-n") == 0) {
            this->just_new_msg = true;
        } else if (strcmp(arr[c].data(), "-a") == 0) {
            this->auth_file = arr[c + 1];
            c++;
            auth_set_flag = 1;
        } else if (strcmp(arr[c].data(), "-o") == 0) {
            this->out_dir = arr[c + 1];
            c++;
            out_dir_set_flag = 1;
        } else if ((error = getaddrinfo(arr[c].data(), nullptr, &hints, &res)) == 0) {

            this->server_name = arr[c].data();
            server_set_flag = 1;

        } else if (hostname_to_ip(arr[c])) {
            this->server_name = arr[c].data();
            server_set_flag = 1;

        } else {
            cerr << "ERROR: Wrong argument #" << c << " " << arr[c].data() << endl;
            delete[](arr);
            showHelp();

        }
        c++;
    }

    //kontrola kombinacie argumentov
    if (port_set_flag == 0 && secure_start) {
        this->port = 995;
    }

    if (auth_set_flag == 0) {
        cerr << "Argument -a is required." << endl;
        showHelp();
    }

    if (out_dir_set_flag == 0) {
        cerr << "Argument -o is required." << endl;
        showHelp();
    }

    if (server_set_flag == 0) {
        cerr << "Argument with server address or name is required" << endl;
        showHelp();
    }


    //uvolnenie alokovanych struktur
    delete[](arr);
    freeaddrinfo(res);
}

bool parser::hostname_to_ip(const string &hostname) {
    return gethostbyname(hostname.data()) != nullptr;
}

void parser::showHelp() {
    cout << "------\t------\t------\t------\t------\t" << endl;
    cout << "Usage: popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] ";
    cout << "[-d] [-n] [-a <auth_file>] [-o <out_dir>]" << endl;
    cout << "Arguments order is arbitrary." << endl;
    cout << "------\t------\t------\t------\t------\t" << endl;
    cout << "-p number of port on remote server" << endl;
    cout << "-T (TLS) connect to remote server securely" << endl;
    cout << "-S (STARTTLS) connect to remote server unsecured and initiate secure communication" << endl;
    cout << "-c name of certification file" << endl;
    cout << "-C name of certification directory" << endl;
    cout << "-d delete all messages from server after download" << endl;
    cout << "-n download and save just new messages" << endl;
    cout << "-a name of file with authentication data" << endl;
    cout << "-o name of folder where messages will be saved " << endl;
    cout << "------\t------\t------\t------\t------\t" << endl;
    exit(0);
}

// https://stackoverflow.com/questions/9670396/exception-handling-and-opening-a-file
void parser::getAuthData() {
    string data, tmp, arr;
    string tmp_arr[2];

    //pomocna premenna na urcenie pozicie ulozenia username alebo password
    int saveflag = 456;

    //pomocna premenna na detekciu hodnoty ktora sa ma ulozit
    int uncounter = 456;     //invalid value by default

    ifstream file;
    file.open(this->auth_file.data(), ios::out | ios::in);
    if (file.fail())
    {
        cerr << "ERROR when opening authentification file." << endl;
        exit(1);
    }

    while (getline(file, tmp)) {
        data.append(tmp);
        data.append(" ");
    }
    file.close();


    stringstream ssin(data);

    //cyklus pre spracovanie autentizacnych udajov
    while (ssin >> arr) {
        if (strcmp(arr.data(), "username") == 0) {
            saveflag = 0;
            uncounter = 2;
        }

        if (strcmp(arr.data(), "password") == 0) {
            saveflag = 1;
            uncounter = 2;
        }

        if (uncounter == 0)
            tmp_arr[saveflag] = arr;
        uncounter--;
    }
    this->username = tmp_arr[0];
    this->password = tmp_arr[1];
}
/**
 *
 * ROZHRANIE PRE PRISTUP K TRIEDNYM PREMENNYM
 *
 **/

long parser::returnPort() {
    return this->port;
}

string parser::returnServer() {
    return this->server_name;
}

string parser::getUsername() {
    return this->username;
}

string parser::getPassword() {
    return this->password;
}

bool parser::secureStart() {
    return this->secure_start;
}

bool parser::do_delete() {
    return this->to_delete;
}

bool parser::do_secure() {
    return this->to_secure;
}

bool parser::is_just_new_msgs() {
    return this->just_new_msg;
}

string parser::getOutdir() {
    return this->out_dir;
}

string parser::getCertdir() {
    return this->certaddr;
}

string parser::getCertfile() {
    return this->certfile;
}
