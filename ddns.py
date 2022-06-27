#!/usr/bin/env python3
"""
Dynamic DNS for Firewall for Vultr
By OurLink, MBRCTV, molexx

credit for https://github.com/andyjsmith/Vultr-Dynamic-DNS
"""
import sys
import time
import requests
import smtplib
import json
import socket
from email.message import EmailMessage
from email.headerregistry import Address
import logging
import yaml
from os.path import exists
from logging.config import dictConfig

#You can disable certain functions while TESTING
do_delete = True
do_create = True
do_email = True

# These settings adjust the internal looping if wanted.
# Otherwise, you could just use cron to set a schedule for running
loop_forever = False  # set to True for continuous looping
sleep_duration_secs = 60

# Use for establishing some logging if desired
log_cfg = ''
if exists('logging.yaml'):
    with open('logging.yaml', 'r') as f:
        log_cfg = yaml.safe_load(f.read())

if log_cfg:
    dictConfig(log_cfg)
else:
    #logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"))
    #logging.basicConfig(level="DEBUG")
    logging.basicConfig(level="INFO")

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)

# Import the values from the configuration file
with open("ddns_config.json") as config_file:
    config = json.load(config_file)  # read ddns_config.json and convert JSON to Python

# Load the ddns_config data
global_api_key = config.get("api_key")
global_ddns_domain = config.get("ddns_domain")
global_email = config.get("email")
firewalls = config.get("firewalls")
logger.info("Starting Update of Vultr Firewall Rules")

# Load some pre-requisites for the processing
## 1 Need to get our current IP address
logger.debug("getting public ip...")

if global_ddns_domain:
    # your os sends out a dns query
    ip = socket.gethostbyname(global_ddns_domain)
else:
    ip = requests.get("https://api.ipify.org/").text

logger.info("got public ip: %s", ip)

#always run the loop at least once
loop_again = True
email_txt = "Processing Firewalls \n"

while loop_again:
    found_count = 0
    uptodate_count = 0
    success_count = 0
    fail_count = 0

    for fw in firewalls:
        api_key = fw.get("api_key")
        firewallname = fw.get("firewallname")
        firewallgroup = fw.get("firewallgroup")
        notes = fw.get("notes")

        if not api_key:
            api_key = global_api_key

        if not api_key:
          raise('api_key not defined')

        logger.info("Calling vultr api to get rules for firewall '%s' / '%s'...", firewallname, firewallgroup)
        # Get the list of firewall rules from Vultr for the given FireWallGroup
        res = requests.get("https://api.vultr.com/v2/firewalls/" +
                                            firewallgroup + "/rules", headers={"Authorization": "Bearer " + api_key})

        logger.debug("vultr api returns res: %s", res)
        restxt = res.text

        logger.debug("vultr api returns body: %s", restxt)

        res_dict = json.loads(restxt)
        raw_rules = res_dict['firewall_rules']
        logger.debug("parsed existing rules: %s", raw_rules)

        email_txt = email_txt + " %s / Group: %s \n" % (firewallname, firewallgroup)

        # Make a new varible with the vultr ip
        v_ip = None

        logger.info("  Beginning check of %s existing rules for rules with note '%s'...", len(raw_rules), notes)        
        for rule in raw_rules:
            if rule["notes"] == notes:
                found_count = found_count + 1
                v_ip = rule["subnet"]

                # Config error when note is added to rule without IP in Vultr firewall
                if not v_ip:
                    logger.warning("  - Configuration error, this rule has note %s but no ip was found.", notes)
                    continue

                # Continue (no changes) - if Rule IP is already updated
                if v_ip == ip:
                    logger.info("  - Rule %s Port: %s is up-to-date with ip %s \n", rule['id'] , rule['port'], ip)
                    uptodate_count = uptodate_count + 1
                    continue

                logger.info("  - IP has changed since last checking.")
                logger.info("  - Old IP on Vultr: %s, current Device IP: %s", v_ip, ip )

                delete_url = "https://api.vultr.com/v2/firewalls/" + firewallgroup + "/rules/" + str(rule['id'])
                logger.debug("  - Deleting vultr rule by sending a DELETE to '%s'...", delete_url)
                if do_delete:
                    delete_response = requests.delete(delete_url,
                                                headers={"Authorization": "Bearer " + api_key}
                    )
                    if delete_response.status_code == 204:
                        logger.debug("  - Current rule with note '%s' for port %s has been deleted ", notes, rule['port'])
                    else:
                        fail_count = fail_count + 1
                        vultr_error = "  - Could not delete rule '%s': res: '%s', res.text: '%s'" % (rule, delete_response, delete_response.text)
                        logger.warning(vultr_error)
                        email_txt = email_txt + "  - Rule %s / Note %s / Port %s failed delete. \n" % (rule['id'], notes, rule['port'])
                        continue

                rule['subnet'] = ip

                #bug in vultr api?
                if not "ip_type" in rule:
                    rule["ip_type"] = rule["type"]

                logger.debug("  - Creating new vultr rule: %s ", rule)

                rule_json = json.dumps(rule, indent = 2)

                if do_create:
                    create_response = requests.post("https://api.vultr.com/v2/firewalls/" + firewallgroup + "/rules",
                                             data=rule_json,
                                             headers={"Authorization": "Bearer " + api_key}
                    )
                    if create_response.status_code == 201:
                        logger.info("  - Rule %s with port %s IP has been updated to %s", rule['id'], rule['port'], ip)
                        email_txt = email_txt + "  - RuleID %s Port:%s was updated! \n" % (rule['id'], rule['port'])
                        success_count = success_count + 1
                    else:
                        vultr_error = "Could not add rule '%s': res: '%s', res.text: '%s'" % (rule_json, create_response, create_response.text)
                        logger.warning(vultr_error)
                        email_txt = email_txt + "  - RuleID %s / Note %s / Port %s failed create. \n" % (rule['id'], notes, rule['port'])
                        fail_count = fail_count + 1
                        continue

        #end loop around vultr firewall rules

        email_txt = email_txt + " Completed Processing Firewall Rule \n"
        
        if found_count == 0:
            logger.warning("No rules found with notes '%s'.", notes)
            email_txt = email_txt + "  - No rules found with notes '%s'." % (notes)
            continue

        total_count = success_count + fail_count + uptodate_count

        if found_count != total_count:
            logger.warning("%s rules were found with notes '%s' but %s rules were processed", found_count, notes, total_count)
            email_txt = email_txt + "%s rules were found with notes '%s' but %s rules were processed. \n" % (found_count, notes, total_count)
            continue

        updated_count = success_count + fail_count

        if updated_count == 0:
            logger.info("  %s rule(s) found with note '%s' were already up-to-date with current ip %s.", found_count, notes, ip)
            email_txt = email_txt + "%s rule(s) found with note '%s' were already up-to-date with current ip %s." % (found_count, notes, ip)
            continue

    # end loop around configured firewalls

    if do_email:
        from_email = global_email.get("from_email")
        to_email = global_email.get("to_email")
        login = global_email.get("login")
        password = global_email.get("password")
        from_name = global_email.get("from_name")
        smtp_server = global_email.get("smtp_server")

        msg = EmailMessage()
        msg.set_content(email_txt)
        msg['Subject'] = '[VultrIP] IP UPDATE'
        msg['From'] = from_email
        msg['To'] = ', '.join(to_email)

        logger.info("Sending email using smtp server %s: %s", smtp_server, msg)

        try:
            server = smtplib.SMTP(smtp_server, 587)
            server.ehlo()
            server.starttls()
            server.login(login, password)
            server.send_message(msg)
            server.close()
            logger.info("Successfully sent confirmation email to '%s'", to_email)
        except Exception as e:
            logger.exception("Failed to send email using %s", smtp_server)


    if loop_forever:
        logger.debug("looping forever, sleeping for %s s...", sleep_duration_secs)
        time.sleep(sleep_duration_secs)
    else:
        logger.debug("looping is disabled, set loop_forever = True to loop forever with a delay")
        loop_again = False

# end loop on 'loop'
