# Application
This application is set up to do the following work: 
* Collect STIX files from free STIX servers
* Find relevant information regarding ports, piv4 addresses and protocols from the STIX files
* Verify if the IPv4 addresses are active by using shodan.io (Need to register to get your own key for this to work)
* Create alert rules for snort. Program gives output to C:\Snort\rules\local.rules

# Environment
The following libreries has to be installed in the environment to make this program run:
* pip install pysimplegui
* pip install asyncio
* pip install cabby
* pip install taxii2-client
* pip install --pre scapy[basic]
* pip install shodan
* pip install stix2-elevator
* pip install spacy 
  An emty model is used, so no need to download model seperatly
* pip install Pympler
* pip install aiosqlite
