/*
 ***********************************************************************************************************************
 * File: scanner.cpp
 * Description: This file definitions of support functions and member functions that are part of scanning
 *              functionalities.
 * Functions:
 *           Port
 *              Port ()
 *              PortToXML ()
 *              NMAPsCVulnScan ()
 *           Host
 *              Host ()
 *              AddPortToHost ()
 *              HostToXML ()
 *              GetOpenPorts ()
 *              PrintOpenNMAPSummary ()
 *              NMAPScriptScan ()
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#include "scanner.hpp"


/*
 * This function instantiates a new object of Port class.
 * :arg: id, reference to the const string object holding the portid.
 * :arg: state, reference to the const string object holding the current state of the port.
 * :arg: service, reference to the const string object holding the name of the service running on the port.
 *       Default value is 'N/A'.
 */
Port::Port (const std::string &id, const std::string &status, const std::string &name) 
            : portid (id), state (status), service (name) {

} /* End of Port () */


/*
 * This function serializes the port object of the target into XML node and returns the node.
 * :arg: parentNode, reference to the XML parent node.
 * :return: XML node to the serialized port object.
 */
pugi::xml_node Port::PortToXML (pugi::xml_node &parentNode) {

    pugi::xml_node nodePort = parentNode.append_child ("Port");
    nodePort.append_attribute ("portid") = portid.c_str ();
    nodePort.append_child ("state").text () = state.c_str ();
    nodePort.append_child ("service").text () = service.c_str ();
    nodePort.append_child ("product").text () = product.c_str ();
    nodePort.append_child ("version").text () = version.c_str ();
    nodePort.append_child ("osname").text () = osName.c_str (); 

    if (scansCompleted.size () > 0) {
        pugi::xml_node nodeScansCompleted = nodePort.append_child ("scanscompleted");
        for (const auto &scan : scansCompleted) {
            nodeScansCompleted.append_child ("scan").text () = scan.c_str ();
        }    
    }
    if (scansFailed.size () > 0) {
        pugi::xml_node nodeScansFailed = nodePort.append_child ("scansfailed");
        for (const auto &scan : scansFailed) {
            nodeScansFailed.append_child ("scan").text () = scan.c_str ();
        }
    }
    if (vulnerabilities.size () > 0) {
        pugi::xml_node nodeVulnerabilities = nodePort.append_child ("vulnerabilities");
        for (const auto &vulnerability : vulnerabilities) {
            nodeVulnerabilities.append_child ("scan").text () = vulnerability.c_str ();
        }
    }
    if (additionalInfo.size () > 0) {
        pugi::xml_node nodeAddInfo = nodePort.append_child ("additionalinfo");
        for (const auto &info : additionalInfo) {
            nodeAddInfo.append_child ("info").text () = info.c_str ();
        }
    }

    return nodePort;

} /* End of PortToXML () */


/*
 * This function runs NMAP script scan, both default and vulnerability scans, against the target on the port object,
 * parses the result and update the port object as identified.
 * :arg: address, reference to the string object holding the target address.
 * :arg: mastterLog, reference to the Logger object to which the messages are to be logged.
 * :return: ReturnCode object denoting success/failure of the operation.
 */
ReturnCodes Port::NMAPsCVulnScan (const std::string &address, Logger &masterLog) {

    std::string command {};
    std::stringstream portOptional {};
    std::stringstream output {};
    pugi::xml_document document {};
    std::string xmlDeep = DIR_PORTS + portid + ".xml";
    std::string logFile = DIR_LOGS + portid + ".log";
    Logger portLog (logFile);
    portLog.Header (portid);

    portOptional << "Port: " << portid;
    masterLog.Log (INFO, MOD_NMAP_SCRIPT, INFO_NMAP_SCV_SCAN, false, portOptional);
    portLog.Log (INFO, MOD_NMAP_SCRIPT, INFO_NMAP_SCV_SCAN, false);
    std::unordered_map <std::string, std::string> placeHolders = {
        {ID, portid},
        {XML_FILE, xmlDeep},
        {TARGET, address}
    };
    command = ReplacePlaceHolders (BASE_NMAP_SCRIPT_SCAN, placeHolders);
    /* Executing NMAP scan */
    if (ExecuteSystemCommand (command, output) == FAIL_CMD_EXEC) {
        portLog.Log (FAIL, MOD_NMAP_SCRIPT, FAIL_NMAP_CMD, false);
        masterLog.Log (FAIL, MOD_NMAP_SCRIPT, FAIL_NMAP_CMD, true, portOptional);
        scansFailed.push_back (MOD_NMAP_SCRIPT);
        portLog.Footer ();
        return FAIL_NMAP_SCRIPT_SCAN;
    }
    portLog.Log (PASS, MOD_NMAP_SCRIPT, PASS_NMAP_CMD, false);
    masterLog.Log (PASS, MOD_NMAP_SCRIPT, PASS_NMAP_CMD, false, portOptional);
    /* Parsing XML document */
    if (!document.load_file (xmlDeep.c_str ())) {
        portLog.Log (FAIL, MOD_NMAP_SCRIPT, FAIL_XML_PARSE, false);
        masterLog.Log (FAIL, MOD_NMAP_SCRIPT, FAIL_XML_PARSE, true, portOptional);
        scansFailed.push_back (MOD_NMAP_SCRIPT);
        portLog.Footer ();
        return FAIL_NMAP_SCRIPT_SCAN;
    }
    portLog.Log (PASS, MOD_NMAP_SCRIPT, PASS_XML_PARSE, false);
    masterLog.Log (PASS, MOD_NMAP_SCRIPT, PASS_XML_PARSE, false, portOptional);
    
    pugi::xml_node nodeHost = document.child ("nmaprun").child ("host");
    /* Extracting service information */
    pugi::xml_node nodePort = nodeHost.child ("ports").child ("port");
    pugi::xml_node nodeService = nodePort.child ("service");
    service = nodeService.attribute ("name").as_string ();
    product = nodeService.attribute ("product").as_string ();
    version = nodeService.attribute ("version").as_string ();
    
    /* Extracting OS information */
    pugi::xml_node nodeOS = nodeHost.child ("os").child ("osmatch");
    if (!nodeOS.empty ()) { osName = nodeOS.attribute ("name").value (); }
    else { osName = "N/A"; }

    /* Extracting Vulnerability Information */
    pugi::xml_node nodeScript;
    for (nodeScript = nodePort.child ("script"); nodeScript; nodeScript = nodeScript.next_sibling ("script")) {
        std::string scriptID = nodeScript.attribute ("id").value ();
        std::string scriptOP = nodeScript.child_value ();
        std::stringstream optional {};
        optional >> scriptID;

        if (scriptOP.find ("vulnerable") != std::string::npos) {
            vulnerabilities.push_back (scriptID);
            portLog.Log (PASS, MOD_NMAP_SCRIPT, PASS_VULN_FOUND, false, optional);
        }
        else {
            portLog.Log (FAIL, MOD_NMAP_SCRIPT, FAIL_VULN_FOUND, false, optional);
        }
    }
    scansCompleted.push_back (MOD_NMAP_SCRIPT);

    portLog.Log (PASS, MOD_NMAP_SCRIPT, PASS_NMAP_SCRIPT_SCAN, false);
    masterLog.Log (PASS, MOD_NMAP_SCRIPT, PASS_NMAP_SCRIPT_SCAN, true, portOptional);

    if (vulnerabilities.size () < 1) {
        portLog.Log (INFO, MOD_NMAP_SCRIPT, FAIL_VULN_FOUND, false);
        masterLog.Log (INFO, MOD_NMAP_SCRIPT, FAIL_VULN_FOUND, true, portOptional);
        portLog.Footer ();
    }
    else {
        portLog.Log (INFO, MOD_NMAP_SCRIPT, PASS_VULN_FOUND, false);
        masterLog.Log (INFO, MOD_NMAP_SCRIPT, PASS_VULN_FOUND, true, portOptional);
    }
    return PASS_NMAP_SCRIPT_SCAN;
} /* End of NMAPsCVulnScan () */


/*
 * This function instantiates a new object of Host class.
 * :arg: address, reference to the const string holding the validated IP address of the target.
 */
Host::Host (const std::string &address) : address (address) {

    numOpen = 0;
    numFiltered = 0;

} /* End of Host () */


/*
 * This function adds the given port object to the Host object, based on the current state of the port, to either
 * openPorts or filteredPorts.
 * :arg: port, Port object containing all pertaining information, that is to be added to the Host object.
 */
void Host::AddPortToHost (const Port &port) {

    if (port.state == STATE_OPEN) {
        openPorts.push_back (port);
        numOpen++;
    }
    else if (port.state == STATE_FLTR) {
        filteredPorts.push_back (port);
        numFiltered++;
    }

} /* End of AddPortToHost () */


/*
 * This function serializes the host object of the target into XML format and saves it into a file with the given name.
 * :arg: fileName, reference to the string holding the file name to which to save the serialized Host object.
 */
void Host::HostToXML (const std::string &fileName) {

    std::lock_guard <std::mutex> lock (mtx);
    pugi::xml_document document;
    pugi::xml_node nodeHost = document.append_child ("Host");
    nodeHost.append_attribute ("Address") = address.c_str ();
    nodeHost.append_attribute ("NumFiltered") = numFiltered;
    nodeHost.append_attribute ("NumOpen") = numOpen;

    pugi::xml_node nodeOpen = nodeHost.append_child ("OpenPorts");
    for (auto &port : openPorts) {
        port.PortToXML (nodeOpen);
    }
    pugi::xml_node nodeFilter = nodeHost.append_child ("FilteredPorts");
    for (auto &port : filteredPorts) {
        port.PortToXML (nodeFilter);
    }
    document.save_file (fileName.c_str ());
} /* End of HostToXML () */


/*
 * This function runs a NMAP scan against the target to identify open and filtered ports along with their respective
 * service names, if available.
 * :arg: logFile, reference to the Logger object to which to messages are to be logged.
 * :return: ReturnCode object denoting success/failure of the operation.
 */
ReturnCodes Host::GetOpenPorts (Logger &logFile) {

    std::string command {};
    std::stringstream output {};
    std::string xmlOpen = DIR_BASE + "OpenPorts.xml";
    std::unordered_map <std::string, std::string> placeHolders = {
        {XML_FILE, xmlOpen},
        {TARGET, address},
    };
    command = ReplacePlaceHolders (BASE_NMAP_OPEN_SCAN, placeHolders);
    logFile.Log (INFO, MOD_PORT_NMAP, INFO_NMAP_PORT_SCAN, true);
    
    if (ExecuteSystemCommand (command, output) != PASS_CMD_EXEC) {
        logFile.Log (FAIL, MOD_PORT_NMAP, FAIL_NMAP_CMD, true);
        return FAIL_NMAP_PORT_SCAN;
    }
    logFile.Log (PASS, MOD_PORT_NMAP, PASS_NMAP_CMD, false);

    /* Parsing XML file */
    pugi::xml_document document;
    if (!document.load_file (xmlOpen.c_str ())) {
        logFile.Log (FAIL, MOD_PORT_NMAP, FAIL_XML_PARSE, true);
        return FAIL_NMAP_PORT_SCAN;
    }
    logFile.Log (PASS, MOD_PORT_NMAP, PASS_XML_PARSE, true);
    pugi::xml_node nodePort;
    pugi::xml_node nodePorts = document.child ("nmaprun").child ("host").child ("ports");
    /* Loop through port nodes to identify port states, their respective portids, states & services */
    for (nodePort = nodePorts.first_child (); nodePort; nodePort = nodePort.next_sibling ("port")) {
        std::string id {}, status {}, name {};
        id = nodePort.attribute ("portid").value ();
        status = nodePort.child ("state").attribute ("state").value ();
        name = nodePort.child ("service").attribute ("name").value ();
        
        if (name.empty ()) { name = "N/A"; }

        if (status != STATE_CLSD) { AddPortToHost (Port (id, status, name)); }
    }
    return PASS_NMAP_PORT_SCAN;
} /* End of GetOpenPorts () */


/*
 * This function prints out a summary of all the ports identified from GetOpenPorts ().
 * :arg: logFile, reference to the Logger object to which to messages are to be logged.
 */
void Host::PrintOpenNMAPSummary (Logger &logFile) {

    if (numFiltered > 0) {
        std::stringstream optional {};
        optional << "\n\t" << numFiltered << " port(s) filtered on the target.\n";
        for (size_t index = 0; index < filteredPorts.size (); index++) {
            const auto &port = filteredPorts [index];
            optional << "\t" << "[+] " << std::setw (5) << std::right << port.portid << " : " << port.service;

            if (index != filteredPorts.size () - 1) {
                optional << "\n";
            }
        }
        logFile.Log (PASS, MOD_NMAP_SUM, PASS_FLTR_FOUND, true, optional);
    }
    else {
        logFile.Log (INFO, MOD_PORT_NMAP, FAIL_FLTR_FOUND, true);
    }

    if (numOpen > 0) {
        std::stringstream optional {};
        optional << "\n\t" << numOpen << " port(s) open on the target.\n";
        for (size_t index = 0; index < openPorts.size (); index++) {
            const auto &port = openPorts [index];
            optional << "\t" << "[+] " << std::setw (5) << std::right << port.portid << " : " << port.service;

            if (index != openPorts.size () - 1) {
                optional << "\n";
            }
        }
        logFile.Log (PASS, MOD_NMAP_SUM, PASS_OPEN_FOUND, true, optional);
    }
    else {
        logFile.Log (INFO, MOD_PORT_NMAP, FAIL_OPEN_FOUND, true);
    }
} /* End of PrintOpenNMAPSumary */


/*
 * This function creates necessary threads and make multi-threaded calls to run NMAP scrip scan against the target
 * on the specified port and collect its results.
 * :arg: logFile, reference to Logger object to which the messages are to be logged.
 * :arg: maxThreads, integer denoting the maximum number of threads, default value is MAX_THREADS (20).
 * :return: ReturnCodes object denoting the success/failure of the operation.
 */
ReturnCodes Host::NMAPScriptScan (Logger &logFile, int maxThreads) {
    
    std::vector <std::thread> threads;
    std::vector <std::future <ReturnCodes>> futures;
    logFile.Log (INFO, MOD_NMAP_SCRIPT, INFO_NMAP_SCRIPT_SCAN, true);
    threads.reserve (std::min (maxThreads, static_cast <int> (openPorts.size ())));

    for (Port &port : openPorts) {
        std::promise <ReturnCodes> promise;
        futures.push_back (promise.get_future ());
        threads.emplace_back ([this, &port, logFile, p = std::move (promise)] () mutable {
            ReturnCodes result;
            {
                std::lock_guard <std::mutex> lock (this->mtx);
                result = port.NMAPsCVulnScan (this->address, logFile);
            }
            p.set_value (result);
        });
    }
    for (std::thread &thread : threads) {
        if (thread.joinable ()) {
            thread.join ();
        }
    }
    for (auto &future : futures) {
        ReturnCodes result = future.get ();
        if (result != PASS_NMAP_SCRIPT_SCAN) { /* Need to change */
            /* Success condition */
        }
        else {
            /* Failure condition */
        }
    }
    return PASS_NMAP_SCRIPT_SCAN;
} /* End of NMAPsCVulnScan () */