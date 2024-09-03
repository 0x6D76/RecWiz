/*
 ***********************************************************************************************************************
 * File: tool.hpp
 * Description: This file contains macros, enums and other data structures associated with customizing tool information.
 * 
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#ifndef CPPLOGGER_TOOL_HPP
#define CPPLOGGER_TOOL_HPP
#include <map>
#include <string>
/*
 * Edit the following, on a per-tool basis to best match requirements.
 */

/* Tool Header */
const std::string TOOL = "ReconWizard";
const std::string VER  = "1.0";

/* Modules */
/* Naming convention is that the module names begin with 'MOD_'. */
const std::string MOD_INIT = "Initialization";
const std::string MOD_CLEAN = "Clean-up";
const std::string MOD_PORT_NMAP = "Port Scan";
const std::string MOD_NMAP_SUM = "Ports Summary";
const std::string MOD_NMAP_SCRIPT = "NMAP Script Scan";
const std::string MOD_EXIT = "Exit";

/* Return Codes */
/* Use postive integers for PASS and INFO messages and negative integers for FAIL messages. */
enum ReturnCodes {
    FAIL_VULN_FOUND = -15,
    ANTI_INFO_NMAP_SCV_SCAN,
    ANTI_INFO_NMAP_SCRIPT_SCAN,
    FAIL_NMAP_SCRIPT_SCAN,
    FAIL_OPEN_FOUND,
    FAIL_FLTR_FOUND,
    FAIL_XML_PARSE,
    FAIL_NMAP_CMD,
    FAIL_NMAP_PORT_SCAN,
    ANTI_INFO_NMAP_PORT_SCAN,
    FAIL_ARG_VALID,
    FAIL_ARG_COUNT,
    FAIL_VALIDATE,
    FAIL_CMD_EXEC,
    INTERRUPT_KEYBOARD = -1,
    DUMMY = 0,
    NONE_KEYBOARD = 1,
    PASS_CMD_EXEC,
    PASS_VALIDATE,
    PASS_ARG_COUNT,
    PASS_ARG_VALID,
    INFO_NMAP_PORT_SCAN,
    PASS_NMAP_PORT_SCAN,
    PASS_NMAP_CMD,
    PASS_XML_PARSE,
    PASS_FLTR_FOUND,
    PASS_OPEN_FOUND,
    PASS_NMAP_SCRIPT_SCAN,
    INFO_NMAP_SCRIPT_SCAN,
    INFO_NMAP_SCV_SCAN,
    PASS_VULN_FOUND = 15,
}; /* End of ReturnCodes */

/* Return Messages */
/* Make sure to leave a space after the message, to make adding optional messages presentable. */
static std::map <ReturnCodes, std::string> ReturnMessages = {
    {FAIL_VULN_FOUND, "No vulnerability found, as per the NMAP script scan. "},
    {FAIL_NMAP_SCRIPT_SCAN, "Executing NMAP script scan has failed. "},
    {FAIL_OPEN_FOUND, "No open port found on the target. "},
    {FAIL_FLTR_FOUND, "No filtered port found on the target. "},
    {FAIL_XML_PARSE, "Parsing XML file has failed. "},
    {FAIL_NMAP_CMD, "Execution of the NMAP command has failed. "},
    {FAIL_NMAP_PORT_SCAN, "Probing the target for open and filtered ports has failed. "},
    {FAIL_ARG_VALID, "Given arg(s) invalid. Check and try again. "},
    {FAIL_ARG_COUNT, "Not all args are given. Check usage and try again. "},
    {FAIL_VALIDATE, "Validating the user-supplied args has failed. "},
    {FAIL_CMD_EXEC, "Executing the command has failed. "},
    {INTERRUPT_KEYBOARD, "Keyboard interrupt received from user. Quitting the tool. "},
    {DUMMY, ""},
    {PASS_CMD_EXEC, "Command execution has completed. "},
    {PASS_VALIDATE, "Validation of user-supplied args has completed. "},
    {PASS_ARG_COUNT, "All required args are given. "},
    {PASS_ARG_VALID, "Arg(s) successfully validated "},
    {INFO_NMAP_PORT_SCAN, "Intiating ports scanning on the target. "},
    {PASS_NMAP_PORT_SCAN, "Probing the target for open and filtered ports has completed. "},
    {PASS_NMAP_CMD, "Execution of NMAP command has completed. "},
    {PASS_XML_PARSE, "Parsing XML file has completed. "},
    {PASS_FLTR_FOUND, "Filtered port(s) found oon the target. "},
    {PASS_OPEN_FOUND, "Open port(s) found on the target. "},
    {PASS_NMAP_SCRIPT_SCAN, "Executing NMAP script scan has completed. "},
    {INFO_NMAP_SCRIPT_SCAN, "NMAP script scan against the target has been initiated. "},
    {INFO_NMAP_SCV_SCAN, "Executing NMAP script scan against the target port has been initiated. "},
    {PASS_VULN_FOUND, "Possible known vulnerability found on the port. "},
}; /* End of ReturnMessages */
#endif