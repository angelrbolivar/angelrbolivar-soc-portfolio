## EDR Host Investigation & Containment (LetsDefend Lab)

Completed a hands-on lab on LetsDefend focused on Endpoint Detection and Response (EDR). I reviewed a Windows endpoint's host information and process list, drilled into a specific process (`Coffee.exe`) to examine its parent-child relationship and file hash, checked network connections for unusual outbound activity, reviewed terminal/command history, and practiced isolating the host using the containment feature.

| Host Info & Process List | Process Detail (Coffee.exe) |
|:---:|:---:|
| ![Host info and process list](labs/LetsDefend/EDR/screenshots/edr2.png) | ![Coffee.exe process detail](labs/LetsDefend/EDR/screenshots/edr3.png) |

| Network Connections | Command History |
|:---:|:---:|
| ![Network connections](labs/LetsDefend/EDR/screenshots/edr4.png) | ![Terminal and command history](labs/LetsDefend/EDR/screenshots/edr5.png) |

**Containment action:**

![Host contained](labs/LetsDefend/EDR/screenshots/edr6.png)

This lab helped me get more comfortable navigating an EDR tool and thinking through the basic steps of endpoint investigation and response.
