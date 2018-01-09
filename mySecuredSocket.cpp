//
// Created by kandski on 10/17/17.
//

#include "mySecuredSocket.h"

#define BUFFER_SIZE 1024

mySecuredSocket::mySecuredSocket() {
    this->sockfd = -1;
    this->number_of_downloaded_messages = 0;
    this->port = 995;
    memset(&this->addr, '\0', sizeof(sockaddr_in));
    memset(&this->addr6, '\0', sizeof(sockaddr_in6));
}

mySecuredSocket::~mySecuredSocket() {

    SSL_free(mySSL);
    shutdown(sockfd, 2);
    SSL_CTX_free(ctx);
}


//nadviazanie spojenia so serverom
int mySecuredSocket::connect(long port, string server, string cert_dir, string cert_file, bool to_secure, bool secure_start) {

    this->port = static_cast<uint16_t>(port);
    //kontrola či bol zadany port, ak nebol implicitna priradena hodnota je 995
    if (secure_start && port < 0) {
        this->port = 995;
    }

    this->server = move(server);
    string data;
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
    //ak ani tento neuspel tak vyhodime error
    if (ret) {
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
        inet_pton(addr.sin_family, this->server.data(), &(this->addr.sin_addr));
        //pripojenie na server
        if (::connect(this->sockfd, reinterpret_cast<const sockaddr *>(&this->addr), sizeof(this->addr)) < 0) {
            cerr << "Error when connecting" << endl;
            return 1;
        }
    }
    //IPv6
    else if (rest->ai_family == AF_INET6) {
        this->addr6.sin6_family = AF_INET6;
        this->addr6.sin6_port = htons(this->port);
        inet_pton(addr6.sin6_family, this->server.data(), &(this->addr6.sin6_addr));
        //pripojenie na server
        if (::connect(this->sockfd, reinterpret_cast<const sockaddr *>(&this->addr6), sizeof(this->addr6)) < 0) {
            cerr << "Error when connecting" << endl;
            return 1;
        }
    } else {
        cerr << this->server << " is an unknown format" << res->ai_family << endl;
        return 1;
    }

    /* SSL -T */
    if (secure_start) {
        //nainicializovanie SSL struktury
        mySSLinit(move(cert_dir), move(cert_file));

        //welcome message
        data = this->readData();
        if (!this->checkOK(data)) {
            cerr << "Welcome error" << endl;
            return -1;
        }
    }
    // STARTTLS -S
    else if (to_secure) {

        //welcome message
        data = this->readUnsecuredData();
        if (!this->checkOK(data)) {
            cerr << "Welcome error" << endl;
            return -1;
        }

        //odoslanie poziadavku o naviazanie STARTTLS komunikacie
        this->sendUnsecuredMsg("STLS");
        data = this->readUnsecuredData();
        if (!this->checkOK(data)) {
            cerr << "STLS error" << endl;
            return -1;
        }

        //nainicializovanie SSl struktury
        mySSLinit(cert_dir, cert_file);
    }
    freeaddrinfo(res);
    freeaddrinfo(rest);

    return 0;
}

//odosielanie sprav serveru /*zabezepecene*/
void mySecuredSocket::sendMsg(string message, string param) {
    //defaultna hodnota pre param je prazdny retazec
    string data;
    //ak bol do funkcie zadany parameter ktory sa ma odoslat serveru tak sa konkatenuje ku sprave
    if (param.length() > 0) {
        message.append(" ");
        message.append(param);
    }
    //kazda sprava musi byt ukoncena crlf znakom
    message.append("\r\n");
    //odoslanie spravy
    if (SSL_write(mySSL, message.data(), message.size()) < 0) {
        cerr << "Error when sending message." << endl;
        SSL_free(mySSL);
        shutdown(sockfd, 2);
        SSL_CTX_free(ctx);
        exit(1);
    }
}
//odhlasenie zo servera, potrebne pre ulozenie vsetkych ukonov vykonanych na serveri ako napr. DELETE
int mySecuredSocket::logout(bool is_just_new) {
    this->sendMsg("QUIT");
    string data = this->readData();
    if (!checkOK(data)) {
        cerr << "ERROR when logout" << endl;
        SSL_free(mySSL);
        shutdown(sockfd, 2);
        SSL_CTX_free(ctx);
        exit(1);
    }
    //po odhlaseni sa vypise stav sprav ktore boli stiahnute
    if (is_just_new)
        cout << "Client has downloaded " << this->number_of_downloaded_messages << " new messages." << endl;
    else
        cout << "Client has downloaded " << this->number_of_downloaded_messages << " messages." << endl;
    return 0;
}


//kontrola či zadany subor uz existuje
inline bool file_exists(const string &name) {
    struct stat buffer{};
    return (stat(name.c_str(), &buffer) == 0);
}


int mySecuredSocket::getAllMsgs(string out_dir, bool to_delete, bool just_new_msg) {
    //odosleme prikaz na zistenie poctu sprav na serveri
    this->sendMsg("STAT");
    string data = this->readData();

    // pomocna premenna na kontrolu spravy prijatej po vymazavani spravy zo serveru
    string dele_tmp;
    if (!checkOK(data)) {
        cerr << "ERROR when stat" << endl;
        SSL_free(mySSL);
        shutdown(sockfd, 2);
        SSL_CTX_free(ctx);
        exit(1);
    }

    // inspired by Saman on Stackoverflow
    // source:(https://stackoverflow.com/questions/12510874/how-can-i-check-if-a-directory-exists)
    struct stat st{};
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
        data = this->readData("\r\n.\r\n"); //kazda sprava konci znakom crlf.crlf
        if (!checkOK(data)) {
            cerr << "ERROR when retrieving msg #" << i << endl;
            SSL_free(mySSL);
            SSL_CTX_free(ctx);
            shutdown(sockfd, 2);
            exit(1);
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
                SSL_free(mySSL);
                SSL_CTX_free(ctx);
                shutdown(sockfd, 2);
                exit(1);
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

string mySecuredSocket::readData(string delim) {
    string data;
    ssize_t len = 0;
    //nainicializovanie a vynulovanie vstupneho bufferu
    auto buffer = new char[BUFFER_SIZE];
    memset(buffer, '\0', sizeof(buffer));

    //prijatie spravy
    while ((len = SSL_read(mySSL, buffer, BUFFER_SIZE)) > 0) {
        data.append(buffer, len);
        if (len < 1) {
            len = SSL_get_error(mySSL, len);
            cerr << "Error #" << len << " in read, program terminated" << endl;
            if (len == 6)       //ak je v premennej "len" hodnota 6, je to sprava od serveru na ukoncenie SSL komunikacie
                SSL_shutdown(mySSL);

            SSL_free(mySSL);
            SSL_CTX_free(ctx);
            shutdown(sockfd, 2);
            exit(1);
        }
        //ukoncovacia podmienka ktora kontroluje ci sa koncova cast spravy nerovna zadanemu parametru ukoncenia
        if (data.substr(data.size() - delim.size(), delim.size()) == delim)
            break;
        //ak ano tak ukonci citanie zo serveru
    }
    delete[] (buffer);

    return data;
}

// ziskanie ip adresy z domenoveho mena servera
// inspired by source:
// http://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
void mySecuredSocket::hostname_to_ip(const string &hostname) {
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

//zistenie spravnosti spravy prijatej zo serveru
bool mySecuredSocket::checkOK(string data) {
    if (data.length() < 3) {
        return false;
    }
    return data.substr(0, 1) == "+";
}

//ziskanie message-id zo spravy pomocou regularneho vyrazu
string mySecuredSocket::getMessageID(string data) {
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
string mySecuredSocket::removeDotStuffed(string data){
    regex pattern{R"([\r][\n]\.\.)"};

    data = regex_replace(data, pattern, "\r\n.");
    return data;
}

//autentizacia na serveri pomocou USER/PASS kombinacie
int mySecuredSocket::login(string user, string pass) {
    this->sendMsg("USER", move(user));
    string data = this->readData();

    if (!this->checkOK(data)) {
        cerr << "USER error." << endl;
        SSL_free(mySSL);
        SSL_CTX_free(ctx);
        shutdown(sockfd, 2);
        exit(1);
    }
    this->sendMsg("PASS", move(pass));
    data = this->readData();

    if (!this->checkOK(data)) {
        cerr << "PASS error." << endl;
        SSL_free(mySSL);
        SSL_CTX_free(ctx);
        shutdown(sockfd, 2);
        exit(1);
    }
    return 0;
}

//inicializacia SSL spojenia
void mySecuredSocket::mySSLinit(string cert_dir, string cert_file) {
    //inicializacia vsetkych potrebnych algoritmov
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    meth = TLSv1_2_client_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        cerr << "ERROR when creating SSL context." << endl;
        exit(1);
    }
    mySSL = SSL_new(ctx);
    if (!mySSL) {
        cerr << "ERROR creating ssl structure" << endl;
        SSL_free(mySSL);
        SSL_CTX_free(ctx);
        shutdown(sockfd, 2);
        exit(1);
    }
    //kontrola certifikacnych suborov ak boli zadane
    if (!cert_dir.empty()) {
        if (!SSL_CTX_load_verify_locations(ctx, nullptr, cert_dir.data())) {
            cerr << "ERROR when loading certificate directory." << endl;
            SSL_free(mySSL);
            SSL_CTX_free(ctx);
            shutdown(sockfd, 2);
            exit(1);

        }
    } else if (!cert_file.empty()) {
        if (!SSL_CTX_load_verify_locations(ctx, cert_file.data(), nullptr)) {
            cerr << "ERROR when loading certificate file." << endl;
            SSL_free(mySSL);
            SSL_CTX_free(ctx);
            shutdown(sockfd, 2);
            exit(1);
        }
    } else {
        if(! SSL_CTX_set_default_verify_paths(ctx)){
            cerr << "ERROR when setting default certification locations"<< endl;
            SSL_free(mySSL);
            SSL_CTX_free(ctx);
            shutdown(sockfd, 2);
            exit(1);
        }
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    //previazanie SSL struktury so socketom
    SSL_set_fd(mySSL, this->sockfd);

    //pripojenie na server zabezpecene
    int err = SSL_connect(mySSL);
    if (err < 1) {
        int errcode = SSL_get_error(mySSL, err);
        cerr << "SSL error " << errcode << endl;
        SSL_free(mySSL);
        SSL_CTX_free(ctx);
        shutdown(sockfd, 2);
        exit(1);
    }
    //prijatie a overenie certifikatu zo serveru
    X509 *x;
    if ((x = SSL_get_peer_certificate(mySSL)) != nullptr) {
        if (SSL_get_verify_result(mySSL) == X509_V_OK) {
            // cout << "Certificate succesfully authentificated." << endl;
        } else{
            cout << "Certificate was not authenticated." << endl;
            SSL_free(mySSL);
            SSL_CTX_free(ctx);
            shutdown(sockfd, 2);
            exit(1);
        }

        X509_free(x);
    }
}

//metoda pre nezabezpecene citanie dat zo servera viac v mySocket.cpp
string mySecuredSocket::readUnsecuredData(string delim) {
    string data;
    ssize_t len = 0;
    auto buffer = new char[BUFFER_SIZE];
    memset(buffer, '\0', BUFFER_SIZE);
    while ((len = ::recv(this->sockfd, buffer, BUFFER_SIZE, 0)) > 0) {
        data.append(buffer, static_cast<unsigned long>(len));
        if (data.substr(data.size() - delim.size(), delim.size()) == delim)
            break;
    }
    delete[] (buffer);
    return data;
}

//metoda pre nezabezpecene odosielanie dat na server viac v mySocket.cpp
void mySecuredSocket::sendUnsecuredMsg(string message, string param) {
    string data;
    if (param.length() > 0) {
        message.append(" ");
        message.append(param);

    }
    message.append("\r\n");
    if (::send(this->sockfd, message.data(), message.size(), 0) < 0) {
        cerr << "Error when sending message." << endl;
        return;
    }
}
