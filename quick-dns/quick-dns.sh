#!/bin/bash

# QUICK-DNS.sh
# Description: Quickly obtain info about a domain, such as MX records, SPF, DMARC, RBL stats, and other info.
# Contributors:
#    Notsoano Nimus <postmaster@thestraightpath.email>,
#    CJ Pfenninger <cjpf@charliejuliet.net>
# Repo: https://github.com/NotsoanoNimus/email-security-toolkit/tree/master/quick-dns
# Date [of first use]: 05 March, 2019
##############

######################################################################################
# quick-dns is a script to simplify the gathering of email-related DNS information.
#
# Copyright (C) 2019 "Notsoano Nimus", as a free software project
#  licensed under GNU GPLv3.
#
# This program is free software: you can redistribute it and/or modify it under
#  the terms of the GNU General Public License as published by the Free Software
#  Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
#  this program. If not, see https://www.gnu.org/licenses/.
######################################################################################

# Include common functions.
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
source "${SCRIPTPATH}/../common/common.sh"
if [ $? -ne 0 ]; then
    echo "~~ Failed to source the \"${SCRIPTPATH}/../common/common.sh\" file."
    exit 200
fi


# usage
# -- Usage information for the script. Terse and easy since this isn't a gargantuan script.
function usage() {
    echo "USAGE: $0 \"domain.name [domain.two domain.three ... domain.n]\" [OPTIONS]"
    echo "-- OR -- $0 {-r ipv4-addr | -R ipv6-addr}"
    echo
    echo " Get information about 'domain.name' such as SPF, MX records,"
    echo "  associated IPs, DMARC, RBL stats, and other email-related info."
    echo " Alternatively, do an RBL lookup against the given IP address."
    echo
    echo "OPTIONS:"
    echo "    -n    Don't use any colors."
    echo "    -d    Put the script into debug mode. BEWARE, this will generate"
    echo "           significantly more output as a step-by-step for the script."
    echo "    -r    Check the given IPv4 address against a list of popular DNSBLs."
    echo "    -R    Same as above but with IPv6 addresses (EXPERIMENTAL,TENTATIVE)."
    echo
    echo "NOTES:"
    echo " - Multiple space-separated domains can be passed to this script"
    echo " -- but the list must be double-quoted."
    echo " - You can only check ONE IP ADDRESS at a time with the -R or -r flags."
    exit 1
}

# quickDNS_main
# -- Main function for the script, where the actual actions are taken.
function quickDNS_main() {
    # If the EMAIL_SECURITY_COMMON import isn't defined, then the common functions are not available. Exit!
    [ -z "${EMAIL_SECURITY_COMMON}" ] && echo "The script could not import the required common library, and therefore could not run. Aborting." && exit 1
    # Immediately set up the trap for the cleanup function on exit.
    trap cleanup EXIT
    # Set up the environment with a clean slate, and verify passed arguments.
    initialize "$@"

    # Run RBL Lookup function if -r or -R flag was present.
    if [[ -n "${V4_LOOKUP}" || -n "${V6_LOOKUP}" ]]; then
        if [[ "$(getPTR "${RBL_CHECK_ADDR}")" == "invalid IP" ]]; then
            echo "Invalid IP address provided. Please review the address given and correct any mistakes."
            echo && exit 180
        fi
        # The below will work because only one of the two can be defined anyway for the script to pass initialization.
        echo "Checking RBLs for IP address: ${TC_PURPLE}${V4_LOOKUP}${V6_LOOKUP}${TC_NORMAL}"
        checkAllRBLs "${V4_LOOKUP}${V6_LOOKUP}"
        echo && exit 0
    fi

    # Begin the main loop.
    for fqdn in ${DOMAINS[@]}; do
        # Run the script for a domain. Start by resetting variables.
        clearVars "NAME_SERVER SPF_RECORD DMARC_RECORD MX_RECORD_OUT MX_RECORDS A_RECORD MX_IP_LIST PTR_RECORD FULL_IP REVERSED_IP"
        # Set the DOMAIN variable.
        DOMAIN="${fqdn}"
        # Print the starting banner.
        printBanner "${fqdn}"
        # Get all information for the given FQDN, displaying it along the way.
        getNameServers
        getSPF
        getDMARC
        getMX
        # Reset the list of IP addresses that have already been checked against RBLs.
        #  This 'tracker' actually probably shouldn't be reset, but keeping this for now.
        RBL_CHECKED_IPS=
        RBL_CHECKED_IPS_A=
        # Check the A-record IP against RBLs, then the MX record IP(s).
        RBL_getALookup
        RBL_getMXLookup
        # Output a blank line and continue.
        echo
    done
}

# cleanup
# -- Clean up any temporary files with a trap. This may not be needed but is scaffolding.
function cleanup() {
    :
}

# initialize
# -- Set up the script environment. This function is critical to proper script operation.
function initialize() {
    # Unset some variables, in case they're defined.
    clearVars "DOMAINS MX_IP_LIST NO_COLORS V4_LOOKUP V6_LOOKUP SKIP_GET_DOMAIN PTR_RECORD FULL_IP REVERSED_IP"
    # The first arg to the program must be a QUOTED list of space-separated domains to check.
    #  If the first parameter is instead a '-r' or '-R', skip this step.
    if [[ "${1:0:2}" != "-R" && "${1:0:2}" != "-r" ]]; then
        # If the first parameter does NOT appear to be a list of hostnames/FQDNs, show the usage.
        if [[ -z "$1" || -z `echo "${1}" | grep -Poi '^([a-z0-9\.\-]+\.[a-z]{2,})(\s+[a-z0-9\.\-]+\.[a-z]{2,})*'` ]]; then
            usage
        else
            # Otherwise, set the DOMAINS variable value.
            DOMAINS="${1}"
            # Remove this from the lineup of arguments, to check any options below.
            shift
        fi
    fi
    # DEFAULT_OPTIONS: Default options for the timeout on the 'dig' lookups that aren't fallback lookups.
    DEFAULT_OPTIONS="+time=2 +tries=2 +short"
    # Interpret arguments to the program.
    while getopts dnR:r: opts; do
        case $opts in
            # Disable colors.
            n) NO_COLORS="YES" ;;
            # Set up the IPv4 address value, provided the IPv6 value isn't set.
            r) [[ -n "${V6_LOOKUP}" || -n "${DOMAINS}" ]] \
                && echo "You must use the -r flag with a valid IPv4 address, and without any domains." && usage
                V4_LOOKUP="${OPTARG}" ;;
            # Same here, but vice-versa. This prevents -r and -R from being used simultaneously.
            R) [[ -n "${V4_LOOKUP}" || -n "${DOMAINS}" ]] \
                && echo "You must use the -R flag with a valid IPv6 address, and without any domains." && usage
                V6_LOOKUP="${OPTARG}" ;;
            # Enable debug mode.
            d) set -x ;;
            # Any invalid options? Display the usage/help.
            *) usage ;;
        esac
    done
    # Terminal color setup and dependency check.
    colors "${NO_COLORS}"
    checkDependencies "dig host grep awk sed tr printf cut head tac"
}


################################################################
##################  Script Modules/Functions  ##################
################################################################

# printBanner
# -- Print a header banner for a section (IP or hostname/domain).
# PARAMS:
#   $1 The domain name or IP adress used to print the banner
function printBanner() {
    echo "################################################################################"
    echo "Checking DNS information for ${TC_BOLD}${TC_YELLOW}${1}${TC_NORMAL}..."
}

# clearVars
# -- Clear all variables associated with the below DNS lookup/parsing functions (in the Script Modules section).
function clearVars() {
    for x in "$@"; do unset `echo $x`; done
}

# getNameServers
# -- Choose the first name server returned from a DIG NS and use it for all future queries.
# TODO: add a name-server tester to avoid delays in future lookups.
function getNameServers() {
    NAME_SERVER=$(dig ns ${DEFAULT_OPTIONS} ${DOMAIN} | head -n1)
    # Check to ensure that name-server exists and is a valid host. If not, fall back to GoogleDNS.
    [[ -z "$NAME_SERVER" || -z `host ${NAME_SERVER} | grep -Pv '(NXDOMAIN)|not found'` ]] && NAME_SERVER="8.8.8.8"
    printf "${TC_BLUE}Primary Nameserver${TC_NORMAL}: "
    [[ "${NAME_SERVER}" == "8.8.8.8" ]] \
        && echo "NONE (defaulting to ${TC_BOLD}8.8.8.8${TC_NORMAL} [Google Public DNS])" || echo "${NAME_SERVER}"
}

# getSPF
# -- Get the SPF record(s) for the domain.
# --  Keeping the "grep" below without a "head/tail" operation or pipe,
# --  to tell the user of the script if there are multiple SPF records.
function getSPF() {
    # Try the lookup and check the fallback option as needed.
    SPF_RECORD=$(dig txt ${DEFAULT_OPTIONS} ${DOMAIN} @${NAME_SERVER})
    (checkFallbackLookup "$SPF_RECORD") || SPF_RECORD=$(fallbackLookup "${DOMAIN}" "txt" "1.1.1.1")
    SPF_RECORD=$(echo "${SPF_RECORD}" | grep -i "v=spf1")
    # Still nothing? Set the display text to NONE.
    [ -z "$SPF_RECORD" ] && SPF_RECORD="NONE"
    # If the amount of lines matching 'v=spf1' is greater than one, provide a warning.
    if [[ $(echo "${SPF_RECORD}" | wc -l) -gt 1 ]]; then
        echo "${TC_CYAN}WARNING${TC_NORMAL}: Multiple SPF Records Found! There should only be 1 SPF Record per domain."
        SPF_RECORD=$(echo ${SPF_RECORD} | tr '\n' ';' | sed 's,;$,,')
        oldIFS=${IFS} && IFS=';' read -ra SPF_RECORD <<< ${SPF_RECORD}
        # Provide an indexed SPF_RECORD display.
        for i in "${!SPF_RECORD[@]}"; do
            echo -e "${TC_CYAN}SPF Record ($((${i}+1)))${TC_NORMAL}:\t${SPF_RECORD[${i}]}"
        done
        IFS=${oldIFS}
    else
        # Otherwise, just output the record (even if nothing was found).
        echo -e "${TC_CYAN}SPF Record${TC_NORMAL}:\t${SPF_RECORD}"
    fi
}

# getDMARC
# -- Get the DMARC record for the domain. Nothing really special here.
function getDMARC() {
    # Try the lookup and check the fallback option as needed.
    DMARC_RECORD=$(dig txt ${DEFAULT_OPTIONS} _dmarc.${DOMAIN} @${NAME_SERVER} | head -1 | sed 's/\\//g')
    [ -z "$DMARC_RECORD" ] && DMARC_RECORD="NONE"
    (checkFallbackLookup "$DMARC_RECORD") || DMARC_RECORD=$(fallbackLookup "_dmarc.${DOMAIN}" "txt" "1.1.1.1")
    # Display the record information.
    echo "${TC_RED}DMARC Record${TC_NORMAL}: ${DMARC_RECORD}"
}

# getA
# -- Return the (last-found) A-record for the domain.
function getA() {
    echo "`dig ${DEFAULT_OPTIONS} a ${1} | tail -n1`"
}

# getMX
# -- Get the MX record(s) for the domain.
function getMX() {
    # Try the lookup and check the fallback option as needed.
    MX_RECORDS=$(dig mx ${DEFAULT_OPTIONS} ${DOMAIN} @${NAME_SERVER})
    (checkFallbackLookup "$MX_RECORDS") || MX_RECORDS=$(fallbackLookup "$DOMAIN" "mx" "1.1.1.1")
    MX_RECORDS=$(echo "$MX_RECORDS" | sed -r 's/^(\s|\t)*/\t/g' | tr '\n' ' ')
    # Check to see if the MX_RECORDS variable contains ANYTHING but spaces/tabs/newlines...
    # If it doesn't break out before continuing the function.
    [[ -z "`echo "${MX_RECORDS}" | grep -Pim1 '[a-z0-9\.-]'`" ]] \
        && MX_RECORD_OUT="NONE" && echo -e "${TC_GREEN}MX Record(s)${TC_NORMAL}: NONE\n" && return
    MX_RECORD_OUT=
    for hostname in $MX_RECORDS; do
        # It's an FQDN. The dig should be done against a public DNS since the FQDN can be for a different domain.
        #  When the FQDN is for a different domain, the name-server is very likely to reject the forwarding request.
        if [[ -n `echo "$hostname" | grep -Poi '^[0-9a-z\-\.]+\.[a-z]{2,}\.?$'` ]]; then
            local MX_IP=$(dig a ${DEFAULT_OPTIONS} ${hostname} @8.8.8.8 | head -n1)
            MX_IP_LIST="${MX_IP_LIST} ${MX_IP}"
            hostname="${hostname} \t(Resolved IP: ${MX_IP})\n"
        elif [[ $(isValidIpv6Address "${hostname}") -eq 0 || $(isValidIpv4Address "${hostname}") -eq 0 ]]; then
            # MX host is already an IP address item: no need to resolve it.
            hostname="${hostname}\n"
        else
            # It's either the priority number, or some other invalid particle.
            hostname="${hostname} "
        fi
        # Append the new hostname variable onto the output of the MX record.
        MX_RECORD_OUT="${MX_RECORD_OUT}${hostname}"
    done
    echo -e "${TC_GREEN}MX Record(s)${TC_NORMAL}:\n${MX_RECORD_OUT}\n"
}

# getPTR
# -- Check PTR record for an IPv4 or IPv6 address.
# PARAMS:
#   $1 = IP Address to lookup
function getPTR() {
    local PTR_RECORD=
    # Check the value against the pattern for an IPv4 address.
    local IP4_PATTERN='^((1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})\.){3}(1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})$'
    if [[ $(isValidIpv4Address "${1}") -eq 0 ]]; then
        # Reverse the IPv4 address and append '.in-addr.arpa'.
        local REVERSED_IP="$(printf "%s" "${1}." | tac -s'.')in-addr.arpa"
        # Perform the lookup and filter out the result.
        local PTR_RECORD=$(dig ${DEFAULT_OPTIONS} ptr "${REVERSED_IP}" | tail -n1)
    # If that fails, check for a valid IPv6 address.
    elif [[ $(isValidIpv6Address "${1}") -eq 0 ]]; then
        local REVERSED_IP=$(getIpv6ArpaAddress "${1}")
        local PTR_RECORD=$(dig ${DEFAULT_OPTIONS} ptr "${REVERSED_IP}" | tail -n1)
    # If that fails further, then it matched neither and is not a valid IP.
    else
        local PTR_RECORD="invalid IP"
    fi
    # If no PTR record is defined, set the return value to "not defined".
    [ -z "${PTR_RECORD}" ] && PTR_RECORD="not defined"
    # Return the PTR record.
    printf "${PTR_RECORD}"
}

# RBL_getALookup
# -- Run an RBL check against the web-server/A-record IP of the domain.
function RBL_getALookup() {
    # Set the A_RECORD variable.
    A_RECORD=$(getA ${DOMAIN})
    # Ensure it's defined, and is a valid IPv4 address. If not, skip the RBL check.
    if [[ -z "${A_RECORD}" || $(isValidIpv4Address "${A_RECORD}") -ne 0 ]]; then
        echo "DNS A-Record for ${DOMAIN} isn't defined; skipping A-record RBL check..."
    else
        # As long as the IP hasn't already been checked by RBLs, proceed.
        #  Otherwise, skip with a notification.
        echo "Attempting A-record RBL check for ${A_RECORD}..."
        local PTR_RECORD=$(getPTR "${A_RECORD}")
        echo "  --========--   ${TC_BOLD}${TC_PURPLE}${A_RECORD}${TC_NORMAL} (PTR: ${PTR_RECORD})    --========--  "
        if [[ -z `echo "${RBL_CHECKED_IPS_A}" | grep -Poi "${A_RECORD}"` ]]; then
            lookupIP "${A_RECORD}" "b.barracudacentral.org" "Barracuda RBL"
            RBL_CHECKED_IPS_A="${RBL_CHECKED_IPS_A} ${A_RECORD}"
        else echo "IP ${A_RECORD} has already been checked. Skipping."; fi
    fi
    echo

}

# RBL_getMXLookup
# -- Run an RBL check against all resolved IPs from the MX record entries.
function RBL_getMXLookup() {
    # If there are no MX records, or no IPs were extracred from the list, do nothing.
    [[ "${MX_RECORD_OUT}" == "NONE" || -z "${MX_IP_LIST}" ]] && return
    # RBL Check on Mail Servers in MX records.
    echo "Attempting MX-record RBL check..."
    # So much simpler and cleaner, without performing more unnecessary DNS lookups.
    for i in ${MX_IP_LIST[@]}; do checkAllRBLs "${i}"; done
    echo
}

# checkAllRBLs
# -- Check against all available DNSBL locations for this script.
# PARAMS:
#    $1 = Target IP Address
function checkAllRBLs() {
    # Extract the PTR record from the IP address. If not defined, default.
    local PTR_RECORD=$(getPTR "${1}")
    [ -z "${PTR_RECORD}" ] && PTR_RECORD="not defined"
    # Start the output of the RBL checks.
    echo "  --========--   ${TC_BOLD}${TC_PURPLE}${1}${TC_NORMAL} (PTR: ${PTR_RECORD})    --========--  "
    [[ -n `echo "${RBL_CHECKED_IPS}" | grep -Poi "${1}"` ]] \
        && echo "IP ${1} has already been checked. Skipping." && return 1
    # 20200104 - NOTE: Removed "MegaRBL" due to consistent false-positive results.
    lookupIP "${1}" "b.barracudacentral.org" "Barracuda RBL"
    lookupIP "${1}" "spam.dnsbl.sorbs.net" "SORBS Spam"
    lookupIP "${1}" "dnsbl-1.uceprotect.net" "UCEPROTECTL1"
    lookupIP "${1}" "bl.spamcop.net" "SpamCop"
    lookupIP "${1}" "noptr.spamrats.com" "SpamRats NoPTR (no-PTR-record spammers)"
    lookupIP "${1}" "dyna.spamrats.com" "SpamRats DYNA (suspicious PTR records)"
    lookupIP "${1}" "zen.spamhaus.org" "Spamhaus ZEN"
    lookupIP "${1}" "dnsbl.spfbl.net" "SPFBL"
    lookupIP "${1}" "ubl.unsubscore.com" "LASHBACK"
    lookupIP "${1}" "db.wpbl.info" "WPBL"
    lookupIP "${1}" "cbl.abuseat.org" "Composite Blocking List (CBL)"
    RBL_CHECKED_IPS="${RBL_CHECKED_IPS} ${1}"
    return 0
}

# lookupIP
# -- Run an IP against the given RBL.
# --  This is a sub-function and usually isn't called from a high-level place in the script.
# PARAMS:
#    $1 = Target IP address,
#    $2 = DNSBL location,
#    $3 = (optional) RBL name.
function lookupIP () {
    # Reverse the IP address to prepare it for the DNS record query.
    local RBL_LOOKUP=
    # TODO: Replace this with a TAC call after finding an IP that's guaranteed blacklisted SOMEWHERE.
    for i in {4..1}; do local RBL_LOOKUP="${RBL_LOOKUP}`echo "${1}" | cut -d'.' -f${i}`."; done
    local RBL_LOOKUP="${RBL_LOOKUP}${2}"
    # Running this query against a public DNS service.
    local IS_LISTED=$(dig a ${DEFAULT_OPTIONS} ${RBL_LOOKUP} @8.8.8.8)
    local CHECKING_INDICATOR=
    local CHECKING_RESULT=
    [ -n "$3" ] && local CHECKING_INDICATOR="Checking \"${TC_BOLD}${3}${TC_NORMAL}\" " \
        || local CHECKING_INDICATOR="Checking DNSBL at \"${TC_BOLD}${2}${TC_NORMAL}\" "
    if [ -n "$IS_LISTED" ]; then
        # If the host is listed, attempt to deduce a reason, which is usually provided at the TXT record location.
        local CHECKING_RESULT="[${TC_RED}LISTED${TC_NORMAL}]"
        local LISTED_REASON=$(dig txt ${DEFAULT_OPTIONS} ${RBL_LOOKUP} @8.8.8.8)
        local CHECKING_RESULT=`echo -e "${CHECKING_RESULT}\n ----> Given Reason (if any): ${LISTED_REASON}"`
    else local CHECKING_RESULT="[${TC_GREEN}NOT LISTED${TC_NORMAL}]"; fi
    # Pretty-print the results of the RBL check.
    printf "%-65s : %s\n" "${CHECKING_INDICATOR}" "${CHECKING_RESULT}"
}

# checkFallbackLookup
# -- Check a public DNS server if the chosen Name Server fails or times out on a lookup.
# PARAMS:
#    $1 = Variable of previous DNS lookup.
function checkFallbackLookup() {
    [[ "$1" =~ (timed out|unreachable|NXDOMAIN|not found) ]] && return 1 || return 0
}

# fallbackLookup
# -- Actually do the lookup if the above check returns anything but 0.
# PARAMS:
#    $1 = Record to look up.
#    $2 = Record type (MX, TXT, etc).
#    $3 = Target (public) DNS server.
function fallbackLookup() {
    # Give this DNS lookup a bit more grace with time/tries.
    local FBLKUP=$(dig +time=5 +tries=3 +short "${2}" "${1}" @${3})
    if [[ "${FBLKUP}" =~ (timed out|unreachable|NXDOMAIN|not found) ]] || [ -z "${FBLKUP}" ]; then
        echo "NONE"
    else echo "${FBLKUP}"; fi
}



################################################################
#######################  IP Functions  #########################
################################################################
# NOTE: This section might instead be offloaded to the "Common"
#        folder for the toolkit, if it ends up needed anywhere
#        else in the project.


# isValidIpv4Address
# -- Returns a '0' if the given string represents a valid IPv4 address.
# --  Otherwise, it returns a '1' value.
# PARAMS:
#   $1 = A string representing an IPv4 address, to test for validity.
function isValidIpv4Address() {
    # This function is simply checking a regular expression for a valid address between
    #  0.0.0.0 and 255.255.255.255, where no octet has a number greater than 255, or lower than 0.
    [[ -n `echo "${1}" | grep -Poi '^((1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})\.){3}(1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})$'` ]]
    echo $?
}

# isValidIpv6Address
# -- Returns a '0' if the given string represents a valid IPv6 address.
# --  Otherwise, it returns a '1' value.
# PARAMS:
#   $1 = A string representing an IPv6 address, to test for validity.
function isValidIpv6Address() {
    local STRING_DOUBLE_COLON_COUNT=$(echo "${1}" | grep -o '::' | wc -l)
    local STRING_IMPROPER_COLONS=$(echo "${1}" | grep -Poi ':{3}')
    local STRING_MATCHES_PATTERN=$(echo "${1}" | grep -Poi '^[0-9a-f\:]+$')
    local STRING_BLOCK_SIZE=$(for x in `echo "${1}" | tr ':' ' '`; do printf "$x" | grep -Poi '[0-9a-z]{5,}'; done)
    local STRING_GROUPS_COUNT=$(echo "${1}" | tr ':' ' ' | wc -w)
    # A valid IPv6 address consists of the following requirements:
    #   - 0 or 1 double-colon group,
    #   - no consecutive colon count >2,
    #   - hex characters (and colons) only,
    #   - each 'group' has only 1-4 characters,
    #   - and 1 to 8 'groups' of hex digits.
    # *** Additionally, the double-colon is NECESSARY if (and only if) the group count is less than 8.
    [[ ( ( $STRING_DOUBLE_COLON_COUNT -eq 1 && $STRING_GROUPS_COUNT -ge 1 && $STRING_GROUPS_COUNT -lt 8 ) \
      || ( $STRING_DOUBLE_COLON_COUNT -eq 0 && $STRING_GROUPS_COUNT -eq 8 ) ) \
      && -z "${STRING_IMPROPER_COLONS}" \
      && -n "${STRING_MATCHES_PATTERN}" && -z "${STRING_BLOCK_SIZE}" \
      && $STRING_GROUPS_COUNT -ge 1 && $STRING_GROUPS_COUNT -le 8 ]]
    # Return the result of the boolean calculation above.
    echo $?
}

# getIpv6ArpaAddress
# -- Return a string of a reversed IPv6 address.
# --  Ex: 2001:db8:34::1 --> 1.0.0.0.0.0.[...].4.3.0.0.8.b.d.0.1.0.0.2.ip6.arpa
# PARAMS:
#    $1 = A string value representing an IPv6 address.
function getIpv6ArpaAddress() {
    local GROUPS_COUNT=$(echo "${1}" | tr ':' ' ' | wc -w)
    local EXPANDED_ADDRESS="${1}"
    # If there are fewer than 8 groups, expand the double-colon outward.
    if [[ $GROUPS_COUNT -lt 8 ]]; then
        local EXPANSION_ZEROES=
        for (( i = 0; i < (8 - $GROUPS_COUNT); i++ )); do EXPANSION_ZEROES="${EXPANSION_ZEROES}:0000"; done
        EXPANDED_ADDRESS=$(echo "${EXPANDED_ADDRESS}" | sed -r 's/::/'"${EXPANSION_ZEROES}"':/')
    fi
    # Any groups with fewer than 4 characters should be prepended with zeroes.
    local FULL_IP=
    for group in `echo "${EXPANDED_ADDRESS}" | tr ':' ' '`; do
        local FILLED_GROUP="0000${group}"
        # Spit out the last 4 characters of the string crafted above ("0000****").
        #  If the "group" variable is fewer than 4 characters, this will prepend the right amount of zeroes.
        #  NOTE: This can also be done with a "grep -Poi '[0-9]{4}$'" as well, if the below proves unreliable.
        FULL_IP="${FULL_IP}:${FILLED_GROUP:`echo "${FILLED_GROUP}" | wc -c` - 5:4}"
    done
    # Clean up the : prepended onto this final expanded address.
    local FULL_IP="${FULL_IP:1}"
    # Remove colons, insert a period between each digit, and reverse the entire thing with 'tac -s.'.
    local ARPA_IP_PREFIX=$(printf "${FULL_IP}" | tr -d ':' | sed -r 's/([0-9a-fA-F])/\1./g' | tac -s'.')
    # Return the ARPA_IP_PREFIX variable, appended with '.ip6.arpa'.
    echo "${ARPA_IP_PREFIX}ip6.arpa"
}



################################################################
################################################################
################################################################
################################################################
# Main function.
quickDNS_main "$@"
exit 0
