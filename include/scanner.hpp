/*
 ***********************************************************************************************************************
 * File: scanner.hpp
 * Description: This file contains declarations of constants, support functions, classes and its associated member 
 *              functions, that are part of scanning functionalities.
 *
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#include <future>
#include <thread>
#include "logger.hpp"
#include "pugixml.hpp"
#include "utilities.hpp"

const int MAX_THREADS = 20;
const std::string BASE_NMAP_OPEN_SCAN = "nmap -Pn -T4 -sT --min-rate=2000 -p- -oX $xml $target";
const std::string BASE_NMAP_SCRIPT_SCAN = "nmap -sV -sT -sC --script=vuln -p $id -oX $xml $target";
const std::string STATE_OPEN = "open";
const std::string STATE_FLTR = "filtered";
const std::string STATE_CLSD = "closed";

class Port {
    public:
        std::string portid;
        std::string state;
        std::string service;
        std::string product;
        std::string version;
        std::string osName;
        std::vector <std::string> scansCompleted;
        std::vector <std::string> scansFailed;
        std::vector <std::string> vulnerabilities;
        std::vector <std::string> additionalInfo;
        /* Member Functions */
        Port (const std::string &id, const std::string &status, const std::string &name = "N/A");
        pugi::xml_node PortToXML (pugi::xml_node &parentNode);
        ReturnCodes NMAPsCVulnScan (const std::string &address, Logger &masterLog);
}; /* End of class Port */


class Host {
    private:
        std::string address;
        int numFiltered;
        int numOpen;
        std::vector <Port> openPorts;
        std::vector <Port> filteredPorts;
        std::mutex mtx;
    public:
        Host (const std::string &address);
        void AddPortToHost (const Port &port);
        void HostToXML (const std::string &fileName);
        ReturnCodes GetOpenPorts (Logger &logFile);
        void PrintOpenNMAPSummary (Logger &logFile);
        ReturnCodes NMAPScriptScan (Logger &logFile, int maxThreads = MAX_THREADS);
}; /* End of class Host */