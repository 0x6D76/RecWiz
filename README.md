# ReconWizard
Automated Reconnaissance and Analysis Tool
Designed to be a comprehensive and user-friendly tool, that makes the reconnaissance process more efficient and thorough.

## Features
### 1. Automated Multi-Stage Scans
The built-in scan engine will probe the target mulitple times for different ends.
* Comprehensive initial NMAP scans to discover open ports and services running on them.
* Comprehensive NSE script scans to identify deeper information about the identified ports and services.
* Sequentially run specialized scans tailored to discovered ports and services.
### 2. Context-Aware Scanning
 * Customized scan strategies based on the type of services detected, i.e., probe the target using specialized scan tools tailored to the service identified.
### 3. Dynamic Report Generation
* Detailed reports highlighting the discovered ports, services, versions and vulnerabilities.
* Additional resources and recommendations on exploitation is also provided.

## Potential Use Cases
* **Comprehensive Penetration Testing:** Equip penetration testers with an automated tool for initial reconnaissance, allowing them to focus on deeper analysis and exploitation.
* **Network Security Audits:** Aid organizations in performing thorough security audits, identifying vulnerabilities and weaknesses in their infrastructure.
* **Vulnerability Management and Compliance:** Help security teams manage and track vulnerabilities, ensuring compliance with security standards and regulations.
* **Educational Resource:** Serve as a learning tool for students and professionals to understand network reconnaissance techniques and best practices.

## Usage

*./reconWizard 127.0.0.1*
*./reconwizard localhost*