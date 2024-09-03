/*
 ***********************************************************************************************************************
 * File: logger.hpp
 * Description: This file contains declarations of constants, support functions, class & member functions associated
 *              with logging functionalities.
 * 
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#ifndef CPPLOGGER_LOGGER_HPP
#define CPPLOGGER_LOGGER_HPP
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "tool.hpp"

/* Constant Declarations */
const int PASS =  1000;
const int FAIL = -1000;
const int INFO =  0;
const int WIDTH = 120;
/* Color codes */
const std::string RST = "\x1B[00m";
const std::string RED = "\x1B[31m";
const std::string GRN = "\x1B[32m";
const std::string YEL = "\x1B[33m";
const std::string BLU = "\x1B[34m";
const std::string MAG = "\x1B[35m";
const std::string CYN = "\x1B[36m";
const std::string UNKNOWN = "Ran into an unkown error.";
//const std::string HEADER = TOOL + VER;
const std::string FOOTER = "Exiting the tool";
const std::string LINE = "=============================================================================================="
                         "==========================";

const std::string DIR_CWD = std::filesystem::absolute ("");
const std::string DIR_BASE = DIR_CWD + "RW/";
const std::string DIR_LOGS = DIR_BASE + "Logs/";
const std::string DIR_PORTS = DIR_BASE + "Ports/";
const std::string LOG_RAW = DIR_LOGS + "RW_Master.log";

/* Function Declarations */
const std::string GetReturnMessage (ReturnCodes code);
const std::string GetCurrentTime ();
void InitializeDirectories (const std::vector <std::string>& dirs);

/* Logger class */
class Logger {
    private:
        std::string fileName;
        bool verbose;
    public:
        Logger (std::string nameFile, bool verbose = false);
        void Header (const std::string identifier = GetCurrentTime (), bool skip = true);
        void Footer (bool skip = true);
        void Log (const int severity, const std::string module, const ReturnCodes code, bool uFlag = false, 
                  const std::stringstream& optional = std::stringstream ());
};

#endif