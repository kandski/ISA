#include <iostream>

#include "argparser.h"
#include "mySocket.h"
#include "mySecuredSocket.h"

int main(int argc, char **argv) {
    parser parser_object(argc, argv);
    if (parser_object.secureStart() || parser_object.do_secure()) {
        mySecuredSocket socket;
        int err = socket.connect(parser_object.returnPort(), parser_object.returnServer(),
                                 parser_object.getCertdir(), parser_object.getCertfile(),
                                 parser_object.do_secure(), parser_object.secureStart());
        if (err != 0)
            return 1;


        err = socket.login(parser_object.getUsername(), parser_object.getPassword());
        if (err != 0)
            return 1;


        err = socket.getAllMsgs(parser_object.getOutdir(), parser_object.do_delete(),
                                parser_object.is_just_new_msgs());
        if (err != 0)
            return 1;


        err = socket.logout(parser_object.is_just_new_msgs());
        if (err != 0)
            return 1;

    } else {
        mySocket socket;

        int err = socket.connect(parser_object.returnPort(), parser_object.returnServer());
        if (err != 0)
            return 1;


        err = socket.login(parser_object.getUsername(), parser_object.getPassword());
        if (err != 0)
            return 1;


        err = socket.getAllMsgs(parser_object.getOutdir(), parser_object.do_delete(),
                                parser_object.is_just_new_msgs());
        if (err != 0)
            return 1;


        err = socket.logout(parser_object.is_just_new_msgs());
        if (err != 0)
            return 1;

    }
    return 0;
}
