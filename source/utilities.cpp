/*
 ***********************************************************************************************************************
 * File: utilities.cpp
 * Description: This file contains definitions of functions that are to be used accross the tool or otherwise
 *              unclassifiable.
 * Functions:
 *           UsageExit ()
 *           KeyboardInterrupt ()
 *           ExecuteSystemCommand ()
 *           ValidateArguments ()
 *           ConvertToIPAddress ()
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#include "logger.hpp"
#include "utilities.hpp"

/*
 * This function prints the error message mapped to the code given, prints the usage instruction and quits the tool
 * operation.
 * :arg: code, Returncodes object holding the error code.
 */
void UsageExit (ReturnCodes code) {

    std::cout << RED << GetReturnMessage (code) << RST << std::endl;
    std::cout << BLU << "Usage: " << RST << "reconWizard.out <target address> <verbose flag>" << std::endl;
    std::cout << BLU << "Example: " << RST << "'reconWizard.out target.domain' or 'reconWizard.out 127.0.0.1'";
    std::cout << std::endl;
    exit (-1);
} /* End of UsageExit () */


/*
 * This function handles the keyboard interrupt signal (Ctrl + C) sent by the user, by printing appropriate message
 * and quits the tool operation.
 * :arg: signal, integer denoting the signal received.
 */
void KeyboardInterrupt (int signal) {

    if (signal == SIGINT ) {
        std::cout << GetReturnMessage (INTERRUPT_KEYBOARD) << std::endl;
        exit (-1);
    }
} /* End of KeyboardInterrupt () */


/*
 * This function executes the given command as a system command, copies it to the supplied stringstream object and
 * finally returns the success or failure of the execution.
 * :arg: command, reference to the const string object holding the command to be executed.
 * :arg: output, reference to the stringstream object to which the output is to be copied.
 * :return: Returncodes object denoting the success or failure of the command execution. 
 */
ReturnCodes ExecuteSystemCommand (const std::string &command, std::stringstream &output) {

    char buffer [128] {};
    /* Open a pipe to execute command and capture its output */
    FILE *pipe = popen (command.c_str (), "r");

    if (!pipe) { return FAIL_CMD_EXEC; }
    while (fgets (buffer, sizeof (buffer), pipe) != nullptr) {
        output << buffer;
    }
    pclose (pipe);
    return PASS_CMD_EXEC;
} /* End of ExecuteSystemCommand () */


/*
 * This function validates the user supplied arguments, by first validating the args counts and then the individual 
 * args finally returns the result.
 * :arg: argCount, integer denoting the number of args given.
 * :arg: values, pointer to a pointer of char denoting the values of user supplied args.
 * :arg: address, reference to the string object holding the coverted or validated target IP address.
 * :return: ReturnCodes object denotinng the success or failure of the operation.
 */
ReturnCodes ValidateArguments (int argCount, char **values, std::string &address) {

    std::vector <std::string> directories;
    if (argCount != 2) {
        UsageExit (FAIL_ARG_COUNT);
        return FAIL_ARG_COUNT;   
    }
    if (ConvertToIPAddress (values [1], address) == PASS_ARG_VALID) {
        directories.emplace_back (DIR_BASE);
        directories.emplace_back (DIR_LOGS);
        directories.emplace_back (DIR_PORTS);
        InitializeDirectories (directories);
        return PASS_ARG_VALID;
    }
    UsageExit (FAIL_ARG_VALID);
    return FAIL_ARG_VALID;
} /* End of ValidateArguments () */


/*
 * This function converts the given target address into its corresponding IP address, using getaddrinfo and returns 
 * the result. The purpose of this conversion is to indirectly validate the given address, both domain and IP address.
 * :arg: target, refernce to the target address as supplied by the user.
 * :arg: address, reference to the string object to which the validated/converted IP address is to be copied.
 * :return: ReturnCodes object denoting the whether the given arg is a valid one.
 */
ReturnCodes ConvertToIPAddress (const std::string &target, std::string &address) {

    struct addrinfo *result;
    struct addrinfo temp {};
    memset (&temp, 0, sizeof (temp));
    temp.ai_family = AF_INET;
    temp.ai_socktype = SOCK_STREAM;

    if (getaddrinfo (target.c_str (), nullptr, &temp, &result) != 0) {
        return FAIL_ARG_VALID;
    }
    auto *addr = (struct sockaddr_in*) result->ai_addr;
    address = inet_ntoa (addr->sin_addr);
    freeaddrinfo (result);
    return PASS_ARG_VALID;
} /* End of ConvertToIPAddress () */


/*
 * This function gets a string and replaces the placeholders in it with the corresponding values given as an 
 * unordered map.
 * :arg: phrase, referece to the string on which the placeholders are to be replaced.
 * :arg: placeHolders, reference to the unordered map object containing placeholders and their respective replacements.
 * :return: string holding the placeholder-replaced result.
 */
std::string ReplacePlaceHolders (const std::string &phrase, 
                                 const std::unordered_map <std::string, std::string> &placeHolders) {
    
    std::string result = phrase;
    for (const auto &placeHolder : placeHolders) {
        std::string key = "$" + placeHolder.first;
        size_t position = result.find (key);

        while (position != std::string::npos) {
            result.replace (position, key.length (), placeHolder.second);
            position = result.find (key, position + placeHolder.second.length ());
        }
    }
    return result;
} /* End of ReplacePlaceHolders () */