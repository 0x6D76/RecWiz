/*
 ***********************************************************************************************************************
 * File: logger.cpp
 * Description: This file contains definitions support functions & member functions associated with logging 
 *              functionalities.
 * Functions:
 *           string GetReturnMessage ()
 *           string GetCurrentTime ()
 *           void InitializeDirectories ()
 *           class Logger
 *              Logger ()
 *              void Header ()
 *              void Footer ()
 *              void Log ()
 * 
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#include "logger.hpp"
#include "tool.hpp"


/*
 * This function enumerates the ReturnMessages map structure and returns the message mapped to the given return code.
 * :arg: returnCode, ReturnCodes value indicating the integer value for the message to be fetched.
 * :return: string holding the return message associated with the given code, returns UNKNOWN if code is not found.
 */
const std::string GetReturnMessage (ReturnCodes returnCode) {

    auto find = ReturnMessages.find (returnCode);
    return (find != ReturnMessages.end ()) ? find->second : UNKNOWN;

} /* End of GetReturnMessage () */


/*
 * This function gets the current time, formats it to the required format using strftime and then returns it.
 * :return: string holding the current time in the "%d-%m-%y %H:%M:%S" format.
 */
const std::string GetCurrentTime () {

    time_t now = time (nullptr);
    char timeStamp [21];
    strftime (timeStamp, sizeof (timeStamp), "[%d-%m-%y %H:%M:%S]", localtime (&now));
    return (timeStamp);

} /* End of GetCurrentTime () */


/*
 * This function takes a vector of strings as its parameter, uses them as directory names and creates directories.
 * This function also checks whether the directory already exists and also handles error conditions.
 * :arg: dirs, constant vector of strings holding the name(s) of directories to be created.
 */
void InitializeDirectories (const std::vector <std::string>& dirs) {

    for (const auto &dir : dirs) {
        try {
            if (std::filesystem::exists (dir)) {
                // std::cout << "Dir " << dir << " already exists.\n";
            } else if (std::filesystem::create_directory (dir)) {
                // std::cout << "Dir " << dir << " created.\n";
            }
        } catch (const std::filesystem::filesystem_error &error) {
            std::cout << "Dir " << dir << " creation failed. Error: " << error.what () 
                      << "\nEnsure you have permission to create new directories the current path. " << std::endl;
            exit (-1);
        }
    }

} /* End of InitializeDirectories */


/*
 * This is a constructor function for Logger class.
 * :arg: nameFile, string holding the name of the log file.
 * :arg: flag, bool value indicating whether to set the verbose flag.
 */
Logger::Logger (std::string nameFile, bool flag) : fileName (nameFile), verbose (flag) {
    
} /* End of Logger () */


/*
 * This function formats and prints header to both STDOUT and log file, based on user inputs on tool.hpp.
 * :arg: identifier, string holding the user-supplied identifier, to be printed onto log file. If identifier is
 *       not given, current time is used.
 */
void Logger::Header (const std::string identifier, bool skip) {

    int padding = 0;
    std::stringstream opHeader {};
    std::stringstream flHeader {};
    std::string head = TOOL;
    std::ofstream logFile;
    if (!VER.empty ()) {
         head = head + " (" + VER + ")"; 
    }
    padding = (WIDTH - head.length ()) / 2;
    opHeader << LINE << "\n" << CYN << std::setw (padding + head.length ()) << head << RST << "\n" 
             << LINE << std::endl;

    flHeader << LINE << "\n" << std::setw (padding + identifier.length ()) << identifier << "\n" << LINE << std::endl;
    if (!skip) { std::cout << opHeader.str (); }
    logFile.open (fileName, std::ios::app);
    logFile << flHeader.str ();
    logFile.close ();

} /* End of Header () */


/*
 * This function formats and prints footer to both STDOUT and log file
 */
void Logger::Footer (bool skip) {

    int padding = 0;
    std::stringstream foot {};
    std::ofstream logFile;
    padding = (WIDTH - FOOTER.length ()) / 2;
    foot << LINE << "\n" << std::setw (padding + FOOTER.length ()) << FOOTER << "\n" << LINE << std::endl;
    if (!skip) { std::cout << foot.str (); }
    logFile.open (fileName, std::ios::app);
    logFile << foot.str ();
    logFile.close ();

} /* End of Footer () */


/*
 * This function initially formats the log message based on the arguments given. The formatted log message is then
 * printed to the STDOUT, if either verbose or user flag is set to true. Finally the log message, sans-color is 
 * written to the log file, the instance is initated with.
 * :arg: severity, constant integer indicating the severity of the log message.
 * :arg: module, const string holding the name of the current module.
 * :arg: code, ReturnCodes object indicating the integer to fetch the message.
 * :arg: uFlag, bool value indicating whether to print the log message to STDOUT.
 * :arg: optional, stringstream object holding the optional message.
 */
void Logger::Log (const int severity, const std::string module, const ReturnCodes code, bool uFlag, 
                  const std::stringstream& optional) {

    std::string color;
    std::string strType;
    std::string message;
    std::stringstream strUser;
    std::stringstream strFile;
    std::ofstream logFile;

    message = GetReturnMessage (code);
    switch (severity) {
        case PASS:
            color = GRN;
            strType = "[PASS]";
            break;
        case FAIL:
            color = RED;
            strType = "[FAIL]";
            break;
        case INFO:
            color = YEL;
            strType = "[INFO]";
            break;
    }

    if (verbose || uFlag) {
        strUser << color << strType << RST << GetCurrentTime () << "[" << module << "] " << message;
        if (optional) { strUser << optional.str (); }
        std::cout << strUser.str () << std::endl;
    }

    strFile << strType << GetCurrentTime () << "[" << module << "] " << message;
    if (optional) { strFile << optional.str (); }
    strFile << "\n";
    logFile.open (fileName, std::ios::app);
    logFile << strFile.str ();
    logFile.close ();

} /* End of Log () */