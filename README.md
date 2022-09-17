# Our project 

The main goals: 
- [x] Find your IP 
- [x] Find your net mask 
- [x] Based on above: scan your network and find IP addres of the target 
- [x] Find open ports on machine that you're attacking 
- [x] Find name and OS verision of all services that you found 
- [x] Do brute-force attack on any service (it can fail) 

We done our project through few steps:
- ifconfig to find our local network address and ip, netmask
- created script for full automation

And you can see our results thorugh this screenshots: 

First step was to check active hosts in local network
![foto1](./images/Skanowanie_nmap_aktywnych_hostow.PNG)

Second step was to create script in python to scan local hosts using scapy:
![foto2](./images/skan_aktywnych_hostow_python_step2.PNG)

Third step was to check for open ports on every host:
![foto3](./images/skanowanie_portu.PNG)

Fourth step was to perform brute force atack:
![foto4](./images/brute_force_complited.PNG)

Ready result and overhaul script is ip_scanner.py and its effect is as follows:
![foto5](./images/Ready_Result.PNG)
