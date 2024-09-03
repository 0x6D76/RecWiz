/*
 ***********************************************************************************************************************
 * File: utilities.hpp
 * Description: This file contains declarations of commonly used constants & functions that are to be used across the
 *              tool or otherwise unclassifiable.
 * 
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#ifndef PORTHAWK_UTILITIES_HPP
#define PORTHAWK_UTILITIES_HPP
#include <arpa/inet.h>
#include <csignal>
#include <netdb.h>
#include <stdexcept>
#include "logger.hpp"

/* Placeholders */
const std::string ID        = "id";
const std::string XML_FILE  = "xml";
const std::string TARGET    = "target";

/* Function Declarations */
void UsageExit (ReturnCodes code);
void KeyboardInterrupt (int signal);
ReturnCodes ExecuteSystemCommand (const std::string &command, std::stringstream &output);
ReturnCodes ValidateArguments (int argCount, char **values, std::string &address);
ReturnCodes ConvertToIPAddress (const std::string &target, std::string &address);
std::string ReplacePlaceHolders (const std::string &phrase, 
                                 const std::unordered_map <std::string, std::string> &placeHolders);

#endif