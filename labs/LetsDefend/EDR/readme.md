## EDR Host Investigation & Containment (LetsDefend Lab)

Completed a hands-on lab on LetsDefend focused on Endpoint Detection and Response (EDR). Working inside the EDR interface, I reviewed a Windows endpoint's host information and process list to get a baseline understanding of what was running on the system.

![Host info and process list overview](edr2.png)

I then drilled into a specific process, `Coffee.exe`, examining its parent-child relationship and file hash to understand how process lineage can point to suspicious activity.

![Detailed process view - Coffee.exe, parent process, hash](edr3.png)

I reviewed the host's network connections to check for unusual outbound activity.

![Network connections](edr4.png)

I also looked at terminal/command history to see what actions had been executed on the endpoint.

![Terminal and command history](edr5.png)

Finally, I practiced isolating the host using the containment feature, a key response action for limiting the spread of a potential threat.

![Containment action - host contained](edr6.png)

This lab helped me get more comfortable navigating an EDR tool and thinking through the basic steps of endpoint investigation and response.
