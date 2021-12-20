#!/usr/bin/env python3
"""
Dynamic DNS for Firewall for Vultr
By MBRCTV, molexx

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




#loop_forever = True
loop_forever = False
sleep_duration_secs = 60




#TESTING
do_delete = True
do_create = True
do_email = True
#do_email = False



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
# Import the values from the configuration file
with open("ddns_config.json") as config_file:
    config = json.load(config_file)  # read ddns_config.json and convert JSON to Python


logger.setLevel(logging.DEBUG)



firewalls = config.get("firewalls")
global_api_key = config.get("api_key")
global_email = config.get("email")


#always run at least once
loop_again = True


previous_ip = ''

#if __name__ == '__main__':
while loop_again:
    vultr_error = False
    found_count = 0
    uptodate_count = 0
    success_count = 0
    fail_count = 0

    for fw in firewalls:
        firewallgroup = fw.get("firewallgroup")
        notes = fw.get("notes")
        ddns_domain = fw.get("ddns_domain")
        api_key = fw.get("api_key")
        email = fw.get("email")


        if not api_key:
            api_key = global_api_key

        if not api_key:
          raise('api_key not defined')


        logger.debug("getting public ip...")

        # Get the public IP of the server
        if ddns_domain:
            # your os sends out a dns query
            ip = socket.gethostbyname(ddns_domain)
        else:
            ip = requests.get("https://api.ipify.org/").text

        logger.debug("got public ip: %s", ip)

        if ip == previous_ip:
            #ip not changed since last loop, skip to the delay
            logger.debug("ip not changed since last run, skipping.")
            continue

        previous_ip = ip

        logger.debug("calling vultr api to get rules for group '%s'...", firewallgroup)
        # Get the list of DNS records from Vultr to translate the record name to recordid
        res = requests.get("https://api.vultr.com/v2/firewalls/" +
                                            firewallgroup + "/rules", headers={"Authorization": "Bearer " + api_key})


        logger.debug("vultr api returns res: %s", res)
        restxt = res.text
        logger.debug("vultr api returns body: %s", restxt)
        res_dict = json.loads(restxt)
        raw_rules = res_dict['firewall_rules']
        logger.debug("parsed existing rules: %s", raw_rules)
        logger.debug("checking %s existing rules for rule with note '%s' with ip '%s'...", len(raw_rules), notes, ip)

        # Make a new varible with the vultr ip
        v_ip = None
        for rule in raw_rules:
            if rule["notes"] == notes:
                found_count = found_count + 1
                v_ip = rule["subnet"]

                # Cancel if no records from Vultr match the config file
                if not v_ip:
                    logger.warning("Configuration error, no ip found for note %s.", notes)
                    continue

                # Check if the IP address actually differs from any of the records
                needsUpdated = False
                if v_ip != ip:
                    needsUpdated = True

                # Cancel if the IP has not changed
                if not needsUpdated:
                    #logger.info("your ip is: %s", ip)
                    logger.info("Rule %s is up-to-date with ip %s", rule['id'] , ip)
                    uptodate_count = uptodate_count + 1
                    continue

                logger.info("your IP has changed since last checking.")
                logger.info("Old IP on Vultr: %s, current Device IP: %s", v_ip, ip )

#    "id": 1,
#    "ip_type": "v4",
#    "action": "accept",
#    "protocol": "tcp",
#    "port": "80",
#    "subnet": "192.0.2.0",
#    "subnet_size": 24,
#    "source": "",
#    "notes": "Example Firewall Rule"


                delete_url = "https://api.vultr.com/v2/firewalls/" + firewallgroup + "/rules/" + str(rule['id'])
                logger.debug("Deleting vultr rule by sending a DELETE to '%s'...", delete_url)
                if do_delete:
                    delete_response = requests.delete(delete_url,
                                                headers={"Authorization": "Bearer " + api_key}
                    )
                    if delete_response.status_code == 204:
                        logger.info("Current rule with note '%s' for port %s has been deleted ", notes, rule['port'])
                    else:
                        fail_count = fail_count + 1
                        vultr_error = "Could not delete rule '%s': res: '%s', res.text: '%s'" % (rule, delete_response, delete_response.text)
                        logger.warning(vultr_error)
                        continue


                rule['subnet'] = ip

                #bug in vultr api?
                if not "ip_type" in rule:
                    rule["ip_type"] = rule["type"]

                logger.debug("Creating new vultr rule: %s", rule)

                rule_json = json.dumps(rule, indent = 2)

                if do_create:
                    create_response = requests.post("https://api.vultr.com/v2/firewalls/" + firewallgroup + "/rules",
                                             data=rule_json,
                                             headers={"Authorization": "Bearer " + api_key}
                    )
                    if create_response.status_code == 201:
                        logger.info("user %s has been updated to %s", notes, ip)
                        success_count = success_count + 1
                    else:
                        vultr_error = "Could not add rule '%s': res: '%s', res.text: '%s'" % (rule_json, create_response, create_response.text)
                        logger.warning(vultr_error)
                        fail_count = fail_count + 1
                        continue

        #end loop around rules

        if found_count == 0:
            logger.warning("No rules found with notes '%s'.", notes)
            continue

        total_count = success_count + fail_count + uptodate_count

        if found_count != total_count:
            logger.warning("%s rules were found with notes '%s' but %s rules were processed", found_count, notes, total_count)
            continue

        updated_count = success_count + fail_count

        if updated_count == 0:
            logger.info("%s rule(s) found with note '%s' were already up-to-date with current ip %s.", found_count, notes, ip)
            continue



        if email:
            from_email = email.get("from_email")
            to_email = email.get("to_email")
            login = email.get("login")
            password = email.get("password")
            from_name = email.get("from_name")
            smtp_server = email.get("smtp_server")
        else:
            from_email = global_email.get("from_email")
            to_email = global_email.get("to_email")
            login = global_email.get("login")
            password = global_email.get("password")
            from_name = global_email.get("from_name")
            smtp_server = global_email.get("smtp_server")

        # send email report
        if not from_email:
            logger.info("No from_email configured for this firewall or globally.")
            continue
        else:
            to_address_l = []

        if not smtp_server:
            smtp_server = 'smtp.gmail.com'

        if not login:
            login = from_email


        if not vultr_error:
            email_text = "%s firewall entries with note '%s' have been updated with IP %s" % (success_count, notes, ip)
        else:
            email_text = "Error updating at least one firewall entry with note '%s': %s" % (notes, vultr_error)


        msg = EmailMessage()
        msg.set_content(email_text)
        msg['Subject'] = '[VultrIP] IP UPDATE'
        msg['From'] = from_email
        msg['To'] = ', '.join(to_email)

        logger.info("Sending email using smtp server %s: %s", smtp_server, msg)


        if not do_email:
            continue

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


    # end loop around configured firewalls

    if loop_forever:
        logger.debug("looping forever, sleeping for %s s...", sleep_duration_secs)
        time.sleep(sleep_duration_secs)
    else:
        logger.debug("looping is disabled, set loop_forever = True to loop forever with a delay")
        loop_again = False

# end loop on 'loop'
