//
// Created by kandski on 10/15/17.
//


#include "mySocket.h"


#define BUFFER_SIZE 512

mySocket::mySocket() {
    this->sockfd = -1;
    this->port = 110;
    this->number_of_downloaded_messages = 0;
    memset(&this->addr, '\0', sizeof(sockaddr_in));
    memset(&this->addr6, '\0', sizeof(sockaddr_in6));
}

mySocket::~mySocket() {
    shutdown(this->sockfd, 2);
}

//nadviazanie spojenia so serverom
int mySocket::connect(long port, string server) {
    this->port = static_cast<uint16_t>(port);
    //kontrola či bol zadany port, ak nebol implicitna priradena hodnota je 110
    if (port < 0) {
        this->port = 110;
    }
    this->server = move(server);

    //struktury na zistenie platnosti ip adresy
    struct addrinfo hint{}, *res = nullptr;
    int ret;

    memset(&hint, '\0', sizeof(hint));

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;
    //prvy pokus o zistenie platnosti ip adresy
    ret = getaddrinfo(this->server.data(), nullptr, &hint, &res);
    if (ret) {
        //ak bol neuspesny tak predpokladame ze je zadane meno servera
        //this->validateIpAddress(this->server);
        //a teda ziskame ip adresu z mena
        this->hostname_to_ip(this->server);

    }
    //obnovime strukturu vysledku
    struct addrinfo *rest = nullptr;
    memset(&hint, '\0', sizeof(hint));

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;

    //druhy pokus o ziskanie informácii z ip adresy
    ret = getaddrinfo(this->server.data(), nullptr, &hint, &rest);
    if (ret) {
        //ak ani tento neuspel tak vyhodime error
        cerr << "Invalid address" << endl;
        return 1;
    }
    //inicializacia socketu ak este nie je vytvoreny
    if (sockfd == -1) {
        sockfd = socket(rest->ai_family, SOCK_STREAM, 0);
        if (sockfd == -1) {
            cerr << "Error when creating socket" << endl;
            return 1;
        }
    }
    //podla typu adresy sa rozhodneme aku strukturu nainicializujeme
    //IPv4
    // inspired by
    // source:(https://stackoverflow.com/questions/3736335/tell-whether-a-text-string-is-an-ipv6-address-or-ipv4-address-using-standard-c-s)
    if (rest->ai_family == AF_INET) {
        this->addr.sin_family = AF_INET;
        this->addr.sin_port = htons(this->port);
        inet_pton(addr.sin_family, this->server.data(), &(addr.sin_addr));
        //pripojenie na server
        if (::connect(this->sockfd, reinterpret_cast<const sockaddr *>(&this->addr), sizeof(this->addr)) < 0) {
            cerr << "Error when connecting" << endl;
            shutdown(sockfd, 2);
            return 1;
        }
    }
    //IPv6
    else if (rest->ai_family == AF_INET6) {
        this->addr6.sin6_family = AF_INET6;
        this->addr6.sin6_port = htons(this->port);
        inet_pton(addr6.sin6_family, this->server.data(), &(addr6.sin6_addr));
        //pripojenie na server
        if (::connect(this->sockfd, reinterpret_cast<const sockaddr *>(&this->addr6), sizeof(this->addr6)) < 0) {
            cerr << "Error when connecting" << endl;
            shutdown(sockfd, 2);
            return 1;
        }
    } else {
        cerr << this->server << " is an unknown format" << res->ai_family << endl;
        return 1;
    }
    //Welcome message
    string data = this->readData();
    if (!this->checkOK(data)) {
        cerr << "Welcome error" << endl;
        shutdown(sockfd, 2);
        return -1;
    }

    freeaddrinfo(res);
    freeaddrinfo(rest);
    return 0;
}

//ziskanie message-id zo spravy pomocou regularneho vyrazu
string mySocket::getMessageID(string data) {
    //regulrny vyraz
    regex pattern{R"(message[-]\w+[:][\r\n\ ]+[<].*[@].*[>])", regex_constants::icase};
    //struktura pre ulozenie vysledkov
    smatch matches;
    regex_search(data, matches, pattern);
    //ulozenie prveho a jedineho vyskytu message-id
    data = matches[0];
    data = data.substr(data.find_first_of('<') + 1, (data.size() - 1));
    data = data.substr(0, data.size() - 1);
    return data;
}

//odstranenie duplicitných bodiek zanechanych serverom
string mySocket::removeDotStuffed(string data) {
    regex pattern{R"([\r][\n]\.\.)"};
    data = regex_replace(data, pattern, "\r\n.");
    return data;
}

// ziskanie ip adresy z domenoveho mena servera
// inspired by source:
// http://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
void mySocket::hostname_to_ip(const string &hostname) {
    struct hostent *hostent_object;
    struct in_addr **addr_list;

    if ((hostent_object = gethostbyname(hostname.data())) == nullptr) {
        cerr << "Error when getting address from hostname" << endl;
        return;
    }

    addr_list = reinterpret_cast<in_addr **>(hostent_object->h_addr_list);

    for (int i = 0; addr_list[i] != nullptr;) {
        this->server = inet_ntoa(*addr_list[i]);
        break;
    }
}

//odosielanie sprav serveru /*zabezepecene*/
void mySocket::sendMsg(string msg, string param) {
    //defaultna hodnota pre param je prazdny retazec
    string data;
    //ak bol do funkcie zadany parameter ktory sa ma odoslat serveru tak sa konkatenuje ku sprave
    if (param.length() > 0) {
        msg.append(" ");
        msg.append(param);
    }
    //kazda sprava musi byt ukoncena crlf znakom
    msg.append("\r\n");
    if (::send(this->sockfd, msg.data(), msg.size(), 0) < 0) {
        cerr << "Error when sending message." << endl;
        shutdown(sockfd, 2);
        exit(1);
    }
}

//autentizacia na serveri pomocou USER/PASS kombinacie
int mySocket::login(string user, string pass) {
    this->sendMsg("USER", user);
    string data = this->readData();

    if (!this->checkOK(data)) {
        cerr << "USER error." << endl;
        shutdown(sockfd, 2);
        return -1;
    }
    this->sendMsg("PASS", pass);
    data = this->readData();

    if (!this->checkOK(data)) {
        cerr << "PASS error." << endl;
        shutdown(sockfd, 2);
        return -1;
    }
    return 0;
}

string mySocket::readData(string delim) {
    string data;
    ssize_t len = 0;
    //nainicializovanie a vynulovanie vstupneho bufferu
    auto buffer = new char[BUFFER_SIZE];
    memset(buffer, '\0', sizeof(buffer));

    //prijatie spravy
    while ((len = ::recv(this->sockfd, buffer, BUFFER_SIZE, 0)) > 0) {
        data.append(buffer, static_cast<unsigned long>(len));

        //ukoncovacia podmienka ktora kontroluje ci sa koncova cast spravy nerovna zadanemu parametru ukoncenia
        if (data.substr(data.size() - delim.size(), delim.size()) == delim)
            break;
    }
    delete[](buffer);
    return data;

}
//zistenie spravnosti spravy prijatej zo serveru
bool mySocket::checkOK(string data) {
    if (data.length() < 3) {
        return false;
    }
    return data.substr(0, 3) == "+OK";

}

//odhlasenie zo servera, potrebne pre ulozenie vsetkych ukonov vykonanych na serveri ako napr. DELETE
int mySocket::logout(bool is_just_new) {
    this->sendMsg("QUIT");
    string data = this->readData();
    if (!checkOK(data)) {
        cerr << "ERROR when logout" << endl;
        shutdown(sockfd, 2);
        return -1;
    }
    //po odhlaseni sa vypise stav sprav ktore boli stiahnute
    if (is_just_new)
        cout << "Client has downloaded " << this->number_of_downloaded_messages << " new messages." << endl;
    else
        cout << "Client has downloaded " << this->number_of_downloaded_messages << " messages." << endl;
    return 0;
}

// inspired by
// https://stackoverflow.com/questions/12774207/fastest-way-to-check-if-a-file-exist-using-standard-c-c11-c
inline bool file_exists(const string &name) {
    struct stat buffer{};
    return (stat(name.data(), &buffer) == 0);
}

int mySocket::getAllMsgs(string out_dir, bool to_delete, bool just_new_msg) {
    struct stat st{};
    // pomocna premenna na kontrolu spravy prijatej po vymazavani spravy zo serveru
    string dele_tmp;

    //odosleme prikaz na zistenie poctu sprav na serveri
    this->sendMsg("STAT");
    string data = this->readData();
    if (!checkOK(data)) {
        cerr << "ERROR when stat" << endl;
        shutdown(sockfd, 2);
        return -1;
    }

    // inspired by Saman on Stackoverflow
    // source:(https://stackoverflow.com/questions/12510874/how-can-i-check-if-a-directory-exists)

    if (!(stat(out_dir.data(), &st) == 0 || S_ISDIR(st.st_mode)))   //ak zadany priecinok neexistuje
    {
        mkdir(out_dir.data(), S_IRUSR | S_IWUSR | S_IXUSR);     //tak ho vytvorime
    }

    //vyextrahujeme pocet sprav
    long n = strtol(data.substr(3, 4).data(), nullptr, 10);

    for (int i = 1; i < n + 1; i++) {
        string messageID;
        //postupne ziskavame spravu po sprave
        this->sendMsg("RETR", to_string(i));
        data = this->readData("\r\n.\r\n");  //kazda sprava konci znakom crlf.crlf
        if (!checkOK(data)) {
            cerr << "ERROR when retrieving msg #" << i << endl;
            shutdown(sockfd, 2);
            return -1;
        }

        data.replace(0, data.find_first_of('\n') + 1, "");
        data = data.substr(0, data.size() - 3);

        //ziskame messageID
        messageID = this->getMessageID(data);
        //odstranime prebytocne duplikovane bodky
        data = removeDotStuffed(data);

        string filename;
        //vytvorime cestu pre ulozenie suboru
        //ktora pozostava z priecinka na ulozenie
        filename.append(out_dir).append("/");
        //a messageID
        filename.append("Msg ID ").append(messageID);
        ofstream out;
        int j = 1;

        //ak uz dana sprava je v priečinku stiahnuta a je zadany parameter -n, tak pokracujeme na dalsiu spravu
        if (file_exists(filename)) {
            if (just_new_msg)
                continue;
            //inak ak existuje tak na koniec pridáme identifikátor poradia stiahnutia spravy "-1" "-2" atd.
            filename.append("-").append(to_string(j));
            while (file_exists(filename)) {
                filename = filename.substr(0, filename.size() - 2);
                filename.append("-").append(to_string(j));
                j++;
            }
        }
        //ak je zadany parameter "-d" tak sa odosle prikaz na zmazanie danej spravy zo serveru
        if (to_delete) {
            this->sendMsg("DELE", to_string(i));
            dele_tmp = this->readData();
            if (!checkOK(dele_tmp)) {
                cerr << "ERROR when DELE" << endl;
                shutdown(sockfd, 2);
                return -1;
            }
        }
        //zapis suboru na disk
        out.open(filename);
        out << data;
        out.close();
        //zaevidovanie stahovania spravy
        this->number_of_downloaded_messages++;
    }
    return 0;
}
