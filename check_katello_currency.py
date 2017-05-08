#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A Nagios/Icinga plugin for checking patch currency of hosts managed by
Foreman/Katello or Red Hat Satellite 6
"""

import argparse
import logging
import os
import stat
import json
import datetime
import time
import getpass
from ForemanAPIClient import ForemanAPIClient

__version__ = "0.5.1"
"""
str: Program version
"""
LOGGER = logging.getLogger('check_katello_currency')
"""
logging: Logger instance
"""
SAT_CLIENT = None
"""
ForemanAPIClient: Foreman API client handle
"""
SYSTEM_ERRATA = {}
"""
dict: Errata and parameter information per system
"""
STATE = 0
"""
int: Nagios/Icinga plugin return code
"""



def set_code(return_code):
    """
    This function sets or updates the result code.
    """
    global STATE
    if return_code > STATE:
        #update return code
        STATE = return_code



def get_return_str():
    """
    This function returns the result status based on the state code.
    """
    #get return string
    if STATE == 3:
        return "UNKNOWN"
    elif STATE == 2:
        return "CRITICAL"
    elif STATE == 1:
        return "WARNING"
    else:
        return "OK"



def check_systems():
    """
    This function checks all specified systems for errata counters.
    """
    if options.all_systems:
        #check all systems
        systems = [x for x in SYSTEM_ERRATA]
    else:
        #onle check selected systems
        systems = options.system
    #remove blacklisted systems
    systems = [x for x in systems if x not in options.exclude]

    #check _all_ the systems
    result_text = ""
    perfdata = ""
    for system in systems:
        LOGGER.debug("Checking system '{}'...".format(system))

        #get counters
        try:
            counter = \
            SYSTEM_ERRATA[system]["content_facet_attributes"]["errata_counts"]
        except KeyError as e:
            LOGGER.error("Unable to check system '{}'".format(system))
            exit(2)

        #set perfdata postfix if multiple systems are checked
        if len(systems) > 1:
            perfdata_postfix = "_{}".format(
                system[:system.find(".")].lower()
            )
        else:
            perfdata_postfix = ""

        #set-up/continue text
        if len(result_text) > 0:
            result_text = "{}, ".format(result_text)

        #check bugfix errata
        if counter["bugfix"] >= options.bugs_crit:
            result_text = "{}bugfix errata CRITICAL ({})".format(
                result_text, counter["bugfix"]
            )
            set_code(2)
        elif counter["bugfix"] >= options.bugs_warn:
            result_text = "{}bugfix errata WARNING ({})".format(
                result_text, counter["bugfix"]
            )
            set_code(1)
        else:
            result_text = "{}bugfix errata OK ({})".format(
                result_text, counter["bugfix"]
            )
        #add perfdata
        perfdata = "{} 'bugfix_errata{}'={};{};{};;".format(
            perfdata, perfdata_postfix,
            counter["bugfix"], options.bugs_warn, options.bugs_crit
        )

        #check secuirty errata
        if counter["security"] >= options.security_crit:
            result_text = "{}, security errata CRITICAL ({})".format(
                result_text, counter["security"]
            )
            set_code(2)
        elif counter["security"] >= options.security_warn:
            result_text = "{}, security errata WARNING ({})".format(
                result_text, counter["security"]
            )
            set_code(1)
        else:
            result_text = "{}, security errata OK ({})".format(
                result_text, counter["security"]
            )
        #add perfdata
        perfdata = "{} 'security_errata{}'={};{};{};;".format(
            perfdata, perfdata_postfix, counter["security"],
            options.security_warn, options.security_crit
        )

        #check total errata
        if options.total_warn and options.total_crit:
            if counter["total"] >= options.total_crit:
                result_text = "{}, total errata CRITICAL ({})".format(
                    result_text, counter["total"]
                )
                set_code(2)
            elif counter["total"] >= options.total_warn:
                result_text = "{}, total errata WARNING ({})".format(
                    result_text, counter["total"]
                )
                set_code(1)
            else:
                result_text = "{}, total errata OK ({})".format(
                    result_text, counter["total"]
                )
            #add perfdata
            perfdata = "{} 'total_errata{}'={};{};{};;".format(
                perfdata, perfdata_postfix, counter["total"],
                options.total_warn, options.total_crit
            )

        result_text = "{} for host {}".format(result_text, system)

    #append perfdata if enabled
    if options.show_perfdata:
        result_text = "{} |{}".format(result_text, perfdata)

    #print result and die in a fire
    print "{}: {}".format(get_return_str(), result_text)
    exit(STATE)



def check_stats():
    """
    This function checks general statistics for all managed systems.
    """
    #Retrieving counters - I'm so sorry, pylint...
    bugs_warn = [x for x in SYSTEM_ERRATA if SYSTEM_ERRATA[x]["content_facet_attributes"]["errata_counts"]["bugfix"] >= options.bugs_warn]
    bugs_crit = [x for x in SYSTEM_ERRATA if SYSTEM_ERRATA[x]["content_facet_attributes"]["errata_counts"]["bugfix"] >= options.bugs_crit]
    LOGGER.debug("Bug errata (warning/critical): {}, {}".format(bugs_warn, bugs_crit))
    security_warn = [x for x in SYSTEM_ERRATA if SYSTEM_ERRATA[x]["content_facet_attributes"]["errata_counts"]["security"] >= options.security_warn]
    security_crit = [x for x in SYSTEM_ERRATA if SYSTEM_ERRATA[x]["content_facet_attributes"]["errata_counts"]["security"] >= options.security_crit]
    LOGGER.debug("Security errata (warning/critical): {}, {}".format(bugs_warn, bugs_crit))
    if options.total_warn and options.total_crit:
        #also get total warning/critical counters
        total_warn = [x for x in SYSTEM_ERRATA if SYSTEM_ERRATA[x]["content_facet_attributes"]["errata_counts"]["total"] >= options.total_warn]
        total_crit = [x for x in SYSTEM_ERRATA if SYSTEM_ERRATA[x]["content_facet_attributes"]["errata_counts"]["total"] >= options.total_crit]
        LOGGER.debug("Total errata (warning/critical): {}, {}".format(total_warn, total_crit))

    #calculate outdated systems
    outdated_sys = bugs_warn + bugs_crit + security_warn + security_crit
    if options.total_warn and options.total_crit:
        #also include total warning/critical counters
        outdated_sys = outdated_sys + total_warn + total_crit
    #remove _all_ the duplicates
    outdated_sys = list(set(outdated_sys))

    #get inactive systems
    inactive_sys = [x for x in SYSTEM_ERRATA if is_inactive(SYSTEM_ERRATA[x]["updated_at"])]

    #set-up perfdata
    perfdata = "'systems_outdated'={};;;;".format(len(outdated_sys))

    #get total and inactive systems
    perfdata = "{} 'systems_total'={};;;; 'systems_inactive'={};;;;".format(
        perfdata, len(SYSTEM_ERRATA), len(inactive_sys)
    )

    #check outdated systems
    if len(outdated_sys) >= options.outdated_crit:
        result_text = "outdated systems CRITICAL ({})".format(len(outdated_sys))
        set_code(2)
    elif len(outdated_sys) >= options.outdated_warn:
        result_text = "outdated systems WARNING ({})".format(len(outdated_sys))
        set_code(1)
    else:
        result_text = "outdated systems OK ({})".format(len(outdated_sys))

    #check inactive systems
    if len(inactive_sys) >= options.inactive_crit:
        result_text = "{}, inactive systems CRITICAL ({})".format(
            result_text, len(inactive_sys))
        set_code(2)
    elif len(inactive_sys) >= options.inactive_warn:
        result_text = "{}, inactive systems WARNING ({})".format(
            result_text, len(inactive_sys))
        set_code(1)
    else:
        result_text = "{}, inactive systems OK ({})".format(
            result_text, len(inactive_sys))

    #append perfdata if enabled
    if options.show_perfdata:
        result_text = "{}| {}".format(result_text, perfdata)

    #print result and die in a fire
    print "{}: {}".format(get_return_str(), result_text)
    exit(STATE)



def get_hosts():
    """
    This function returns all hosts including errata information
    """
    #get all the hosts depending on the filter
    filter_url = get_filter(options, "host")
    LOGGER.debug("Filter URL will be '{}'".format(filter_url))
    result_obj = json.loads(
        SAT_CLIENT.api_get("{}".format(filter_url))
    )
    hosts = {}
    for host in result_obj["results"]:
        #found a host!
        if host["name"] not in options.exclude:
            hosts[host["name"]] = {}
            hosts[host["name"]] = host
    return hosts



def is_inactive(timestamp):
    """
    This functions returns whether a particular host seems to be inactive.
    This is done by checking the delta between the current date/time and
    the last update timestamp in the result retrieved by the Foreman API.
    All systems that have not received any Puppet update in the last 2 days
    are defined as inactive.

    :param timestamp: the timestamp retrieved from the API
    :type timestamp: str
    """
    #get current timestamp
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    current_time = datetime.datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
    #get system timestamp from string
    timestamp_time = datetime.datetime.strptime(
        timestamp[0:19], "%Y-%m-%d %H:%M:%S"
    )
    #calculate difference
    if current_time - timestamp_time > datetime.timedelta(days=2):
        return True
    else:
        return False



def validate_filters(options, api_client):
    """
    Ensures using IDs for the Foreman API rather than human-readable names.
    This is done by detecting strings and translating them into IDs.

    :param options: argparse options dict
    :type options: dict
    :param api_client: ForemanAPIClient object
    :type api_client: ForemanAPIClient
    """
    if options.location.isdigit() == False:
        options.location = api_client.get_id_by_name(
            options.location, "location")
    if options.organization.isdigit() == False:
        options.organization = api_client.get_id_by_name(
            options.organization, "organization")
    if options.hostgroup.isdigit() == False:
        options.hostgroup = api_client.get_id_by_name(
            options.hostgroup, "hostgroup")
    if options.environment.isdigit() == False:
        options.environment = api_client.get_id_by_name(
            options.environment, "environment")



def get_filter(options, api_object):
    """
    Sets up a filter URL based on arguments set-up with argpase.

    :param options: argparse options dict
    :type options: dict
    :param api_object: Foreman object type (e.g. host, environment)
    :type api_object: str
    """
    if options.location:
        return "/locations/{}/{}s".format(options.location, api_object)
    elif options.organization:
        return "/organizations/{}/{}s".format(options.organization, api_object)
    elif options.hostgroup:
        return "/hostgroups/{}/{}s".format(options.hostgroup, api_object)
    elif options.environment:
        return "/environments/{}/{}s".format(options.environment, api_object)
    else:
        return "/{}s".format(api_object)



def get_credentials(prefix, input_file=None):
    """
    Retrieves credentials for a particular external system (e.g. Satellite).

    :param prefix: prefix for the external system (used in variables/prompts)
    :type prefix: str
    :param input_file: name of the auth file (default: none)
    :type input_file: str
    """
    if input_file:
        LOGGER.debug("Using authfile")
        try:
            #check filemode and read file
            filemode = oct(stat.S_IMODE(os.lstat(input_file).st_mode))
            if filemode == "0600":
                LOGGER.debug("File permission matches 0600")
                with open(input_file, "r") as auth_file:
                    s_username = auth_file.readline().replace("\n", "")
                    s_password = auth_file.readline().replace("\n", "")
                return (s_username, s_password)
            else:
                LOGGER.warning("File permissions (" + filemode + ")" \
                    " not matching 0600!")
        except OSError:
            LOGGER.warning("File non-existent or permissions not 0600!")
            LOGGER.debug("Prompting for {} login credentials as we have a" \
                " faulty file".format(prefix))
            s_username = raw_input(prefix + " Username: ")
            s_password = getpass.getpass(prefix + " Password: ")
            return (s_username, s_password)
    elif prefix.upper()+"_LOGIN" in os.environ and \
        prefix.upper()+"_PASSWORD" in os.environ:
        #shell variables
        LOGGER.debug("Checking {} shell variables".format(prefix))
        return (os.environ[prefix.upper()+"_LOGIN"], \
            os.environ[prefix.upper()+"_PASSWORD"])
    else:
        #prompt user
        LOGGER.debug("Prompting for {} login credentials".format(prefix))
        s_username = raw_input(prefix + " Username: ")
        s_password = getpass.getpass(prefix + " Password: ")
        return (s_username, s_password)



def parse_options(args=None):
    """Parses options and arguments."""

    desc = '''check_katello_currency.py is used to check systems managed by
    Foreman/Katello or Red Hat Satellite 6.x for outstanding errata.
    Login credentials are assigned using the following shell variables:
    SATELLITE_LOGIN  username
    SATELLITE_PASSWORD  password

    It is also possible to create an authfile (permissions 0600) for usage
    with this script. The first line needs to contain the username, the
    second line should consist of the appropriate password. If you're not
    defining variables or an authfile you will be prompted to enter your
    login information.
    '''
    epilog = '''Check-out the website for more details:
    http://github.com/stdevel/check_katello_currency'''
    parser = argparse.ArgumentParser(description=desc, version=__version__, \
    epilog=epilog)

    #define option groups
    gen_opts = parser.add_argument_group("generic arguments")
    fman_opts = parser.add_argument_group("Foreman arguments")
    stat_opts = parser.add_argument_group("statistic arguments")
    system_opts = parser.add_argument_group("system arguments")
    filter_opts = parser.add_argument_group("filter arguments")
    filter_opts_excl = filter_opts.add_mutually_exclusive_group()

    #GENERIC ARGUMENTS
    #-d / --debug
    gen_opts.add_argument("-d", "--debug", dest="debug", default=False, \
    action="store_true", help="enable debugging outputs")
    #-P / --show-perfdata
    gen_opts.add_argument("-P", "--show-perfdata", dest="show_perfdata", \
    default=False, action="store_true", \
    help="enables performance data (default: no)")

    #FOREMAN ARGUMENTS
    #-a / --authfile
    fman_opts.add_argument("-a", "--authfile", dest="authfile", metavar="FILE",\
    default="", help="defines an auth file to use instead of shell variables")
    #-s / --server
    fman_opts.add_argument("-s", "--server", dest="server", metavar="SERVER", \
    default="localhost", help="defines the server to use (default: localhost)")
    #--insecure
    fman_opts.add_argument("--insecure", dest="ssl_verify", default=True, \
    action="store_false", help="Disables SSL verification (default: no)")

    #STATISTIC ARGUMENTS
    #-y / --generic-statistics
    stat_opts.add_argument("-y", "--generic-statistics", dest="gen_stats", \
    default=False, action="store_true", help="checks for inactive and" \
    " outdated system statistic metrics (default :no)")
    #-u / --outdated-warning
    stat_opts.add_argument("-u", "--outdated-warning", dest="outdated_warn", \
    default=50, metavar="NUMBER", type=int, help="defines outdated systems" \
    " warning percentage threshold (default: 50)")
    #-U / --outdated-critical
    stat_opts.add_argument("-U", "--outdated-critical", dest="outdated_crit", \
    default=80, metavar="NUMBER", type=int, help="defines outdated systems" \
    " critical percentage threshold (default: 80)")
    #-n / --inactive-warning
    stat_opts.add_argument("-n", "--inactive-warning", dest="inactive_warn", \
    default=10, metavar="NUMBER", type=int, help="defines inactive systems" \
    " warning percentage threshold (default: 10)")
    #-N / --inactive-critical
    stat_opts.add_argument("-N", "--inactive-critical", dest="inactive_crit", \
    default=50, metavar="NUMBER", type=int, help="defines inactive systems" \
    " critical percentage threshold (default: 50)")

    #SYSTEM ARGUMENTS
    #-S / --system
    system_opts.add_argument("-S", "--system", dest="system", default=[], \
    metavar="SYSTEM", action="append", help="defines one or multiple" \
    " system(s) to check")
    #-A / --all-systems
    system_opts.add_argument("-A", "--all-systems", dest="all_systems", \
    default=False, action="store_true", help="checks all registered" \
    " systems - USE WITH CAUTION (default: no)")
    #-x / --exclude
    system_opts.add_argument("-x", "--exclude", action="append", \
    default=[], type=str, dest="exclude", metavar="NAME", help="specfies " \
    "particular hosts to ignore (default: no)")
    #-t / --total-warning
    system_opts.add_argument("-t", "--total-warning", dest="total_warn", \
    metavar="NUMBER", type=int, help="defines total errata warning" \
    " threshold (default: empty)")
    #-T / --total-critical
    system_opts.add_argument("-T", "--total-critical", dest="total_crit", \
    metavar="NUMBER", type=int, help="defines total errata critical" \
    " threshold (default: empty)")
    #-i / --important-warning
    system_opts.add_argument("-i", "--security-warning", "--important-warning",\
    dest="security_warn", metavar="NUMBER", type=int, default=10, \
    help="defines security errata warning threshold (default: 10)")
    #-I / --important-critical
    system_opts.add_argument("-I", "--security-critical", \
    "--important-critical", dest="security_crit", metavar="NUMBER", type=int, \
    default=20, help="defines security errata critical threshold (default: 20)")
    #-b / --bugs-warning
    system_opts.add_argument("-b", "--bugs-warning", dest="bugs_warn", \
    type=int, metavar="NUMBER", default=25, help="defines bug package update" \
    " warning threshold (default: 25)")
    #-B / --bugs-critical
    system_opts.add_argument("-B", "--bugs-critical", dest="bugs_crit", \
    type=int, metavar="NUMBER", default=50, help="defines bug package update" \
    " critical threshold (default: 50)")

    #FILTER ARGUMENTS
    #-l / --location
    filter_opts_excl.add_argument("-l", "--location", action="store", \
    default="", dest="location", metavar="NAME|ID", help="filters by a" \
    " particular location (default: no)")
    #-o / --organization
    filter_opts_excl.add_argument("-o", "--organization", action="store", \
    default="", dest="organization", metavar="NAME|ID", help="filters by an" \
    " particular organization (default: no)")
    #-g / --hostgroup
    filter_opts_excl.add_argument("-g", "--hostgroup", action="store", \
    default="", dest="hostgroup", metavar="NAME|ID", help="filters by a" \
    " particular hostgroup (default: no)")
    #-e / --environment
    filter_opts_excl.add_argument("-e", "--environment", action="store", \
    default="", dest="environment", metavar="NAME|ID", help="filters by an" \
    " particular environment (default: no)")


    #parse options and arguments
    options = parser.parse_args()
    return (options, args)



def main(options):
    """Main function, starts the logic based on parameters."""
    global SAT_CLIENT, SYSTEM_ERRATA

    LOGGER.debug("Options: {0}".format(options))
    LOGGER.debug("Arguments: {0}".format(args))

    #check system specification
    if options.all_systems == False and options.gen_stats == False and \
    not options.system:
        LOGGER.error("You need to either specify one or multiple particular" \
        " systems or check statistics!")
        exit(1)

    (sat_user, sat_pass) = get_credentials("Satellite", options.authfile)
    SAT_CLIENT = ForemanAPIClient(
        options.server, sat_user, sat_pass, options.ssl_verify
    )
    #validate filters
    validate_filters(options, SAT_CLIENT)

    #check statistics or systems
    SYSTEM_ERRATA = get_hosts()
    if options.gen_stats:
        check_stats()
    else:
        check_systems()



if __name__ == "__main__":
    (options, args) = parse_options()

    #set logging level
    logging.basicConfig()
    if options.debug:
        LOGGER.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.ERROR)

    main(options)
