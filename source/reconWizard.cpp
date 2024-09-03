/*
 ***********************************************************************************************************************
 * File: reconWizard.cpp
 * Description: This file contains the main function of the tool that kicks off the operation and handles the process
 *              henceforth.
 * Functions:
 *           main ()
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#include "logger.hpp"
#include "scanner.hpp"
#include "utilities.hpp"

int main (int argCount, char **values) {

    std::signal (SIGINT, KeyboardInterrupt);
    std::string address {};
    std::stringstream optional;
    Logger rawLog (LOG_RAW);

    if (ValidateArguments (argCount, values, address) == PASS_ARG_VALID) {
        std::string xmlResult = DIR_CWD + "RW_" + address + ".xml";
        rawLog.Header (address, false); 
        Host host (address);
        rawLog.Log (PASS, MOD_INIT, PASS_ARG_VALID, true);
        host.GetOpenPorts (rawLog);
        host.PrintOpenNMAPSummary (rawLog);
        host.NMAPScriptScan (rawLog);
        host.HostToXML (address + ".xml");
        optional << "Result are stored in XML format with the file name " << address << ".xml";
        rawLog.Log (INFO, MOD_EXIT, DUMMY, true, optional);
        rawLog.Footer (false); 
    } 
} /* End of main () */