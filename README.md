# Dynamic IP update for Vultr Firewall


Vultr does not accept the use of DDNS domains for updating firewall rules. Therefore, this script is intended to update the Vultr Firewall, allowing the updating of firewall rules so that your dynamic IP can be assigned to individual rules automatically.

Using the Vultr API, your access key, and this script you can set your IP to be updated in the Vultr firewall automatically whenever your IP changes.
 
We use this script with over 15 different Vultr VPS servers/firewalls, each with an array of different firewall rules, and it works perfectly.

### Setup

Assuming you have a Vultr Account (if you don't have one, you can use [our affiliate link](https://www.vultr.com/?ref=9160186-8H) and receive $100 credit for the first 30 days). You'll need an account, VPS Server, firewall, and your personal API token.

* Go to the firewall tab, and click 'Add Firewall Group'
* Setup individual firewalls/rules
  * Select the protocol you would like to open for yourself like TCP 
  * Enter the port or range for example `1 - 65535`	
  * Select a source IP - example: `My IP` (not important as the script will update it) 
  * IMPORTANT, add a UNIQUE note to your rule, the script scans the firewall rules for the unique note you assigned. Any rules found that match the note are updated with the new IP assignment. An example note might be "CHANGE THIS IP". The note is case sensitive.
* save the firewall/rules and assign it to a VPS


### Config
Copy the `sample.ddns_config.json` file to `ddns_config.json` and modify the file with your settings for the following;

* Global Settings
  * `api_key` vultr api key
  * `ddns_domain` (Optional) the DDNS domain if you have one otherwise uses the machines IP
* Email
  * `smtp_server` (Optional, defaults to gmail)
  * `login`       (Optional, defaults to from_email) username passed in smtp server authentication
  * `password`    (Optional) smtp server password
  * `from_email`  (Optional) if you want email notification each time the IP changed
  * `to_email`    (Optional) array of emails (can be array with only 1 email)
  * `from_name`   (Optional) sender name
* Firewalls
  * `api_key` (optional) each firewall could be assigned a different API Token for security
  * `firewallname` a firewall name (your choice) to easily identify the groupID from Vultr
  * `firewallgroup` the firewall ID (32 character GUID)
  * `notes` the note your script will scan for in the Firewall/Rules set

You can set `api_key` as global, or set it for each firewall rule.
At this time, you can set `DDNS Domain, Email information as Global`


### Looping
This script contains an internal, configurable loop. To loop forever, with a configurable delay between polls edit `ddns.py` and set `loop_forever` to `True`. The delay time is configurable, defaulting to 60 seconds (can be changed within script).

### Linux Cron
We suggest to use the `crontab -e` command in Linux and establish a recurring execution time via `cron` as opposed to the internal looping.

### Windows Task
For Windows, create a task in Task Scheduler to run every 30 minutes. Follow the Microsoft guide for basic task creation.

### Changelog

#### 2022/06/12 - OurLink
- cleaned up script, more readable 
- resolved some bugs
- modified email message body (more details)
- fixed unix format line endings
- removed individual firewall email processing, now send one email for the entire script regardless of number of firewall/rules updated
- working on better logging settings in `sample.logging.yaml`


#### 20/12/2021 - molexx
- update to vultr API v2
- configurable smtp server
- configurable smtp login/username
- optional loop forever
- more error handling, include info in the email
- don't require logging.yaml
- convert to unix format line endings
- add shebang to the top of the file to allow direct execution `./ddns.py`
- support python 3.5 (for older raspberry pi installs)



ourlink forked this from https://github.com/molexx/VultrFirewallDynamicDNS 

molexx forked this from https://github.com/MBRCTV/VultrFirewallDynamicDNS   

credit for https://github.com/andyjsmith/Vultr-Dynamic-DNS
