#!/bin/bash

# DKIM-VERIFY.sh
: Description: Validate and verify a raw email DKIM signature. Seek and output any errors.
: Author: Zachary Puhl
: Contact: zpuhl@barracuda.com // postmaster@yeethop.xyz
: Date: 17 March, 2019
################


# usage
# -- Display general usage and help for the script.
function usage() {
  echo "USAGE: $0 email-file [OPTIONS]"
  echo "  Verify the validity of the most recent DKIM-Signature header"
  echo "  on a raw email message, and if there are errors, output them."
  echo && exit 1
}

# colors
# -- Initialize terminal colors, if enabled.
function colors() {
  COLORS=$(tput colors 2>/dev/null)
  if [ -n "$COLORS" ]; then
    TC_RED=`tput setaf 1 2>/dev/null`
    TC_GREEN=`tput setaf 2 2>/dev/null`
    TC_YELLOW=`tput setaf 3 2>/dev/null`
    TC_BLUE=`tput setaf 4 2>/dev/null`
    TC_CYAN=`tput setaf 6 2>/dev/null`
    TC_NORMAL=`tput sgr0 2>/dev/null`
    TC_BOLD=`tput bold 2>/dev/null`
  fi
}

# initialize
# -- Set up the script environment. Mainly used to ensure variables are clean.
function initialize() {
  DKIM_SIGNATURE=;EMAIL_FILE=;
  EMAIL_HEADERS=;EMAIL_BODY=;
  SIGNER_PUBKEY=;
}

# errorOutput
# -- Output an error to the terminal and exit with the given code.
# PARAMS: 1 = Accompanying string, 2 = Exit code
function errorOutput() {
  echo "${TC_BOLD}${TC_RED}ERROR${TC_NORMAL}: $1"
  exit $2
}

# extractSignature
# -- Extract the top-most DKIM signature from the message. This will comply
# ---- with either 'flat' DKIM signatures or ones broken up into multiple lines.
function extractSignature() {
  # Set DKIM_SIG to the first "DKIM-Signature" header line, and the 15 lines after
  # -- it. Then, preserve the top line (the DKIM-Signature line) and wipe it from
  # -- the variable with a 'sed' command so only that the 15 lines after remain.
  local DKIM_SIG=$(grep -Pi -A15 -m1 '^DKIM-Signature:' "$1")
  echo "$DKIM_SIG" | grep -Poi '^DKIM-Signature:.*?$' >/tmp/dkim-verify-$$
  local DKIM_SIG=$(echo "${DKIM_SIG}" | sed -r '/^DKIM-Signature:.*?$/d')

  # Preserve the whitespace of the DKIM_SIG variable, echo it into the 'while' loop.
  # -- While there are still lines to read, set TESTVAR to any lines with spaces or
  # -- tabs preceding the content. As soon as TESTVAR doesn't have these, the DKIM
  # -- Signature's indentations have stopped, so we've captured the whole signature.
  IFS=''
  echo "$DKIM_SIG" | \
  while read -r line || [[ -n "$line" ]]; do
    local TESTVAR=$(echo "$line" | grep -Pi '^(\s+|\t+)')
    if [ -n "${TESTVAR}" ]; then echo "${TESTVAR}" >>/tmp/dkim-verify-$$
    else break; fi
  done

  # Cat the constructed temporary file into the DKIM_SIGNATURE variable, then remove the file.
  DKIM_SIGNATURE=$(cat /tmp/dkim-verify-$$)
  rm /tmp/dkim-verify-$$
  # If the signature isn't defined at all, there's nothing to do at all, so quit.
  [ -z "$DKIM_SIGNATURE" ] && return 1
  # Output the clean version of the Signature, then crunch it before leaving.
  echo "${DKIM_SIGNATURE}"
  DKIM_SIGNATURE=$(echo "${DKIM_SIGNATURE}" | tr '\n' ' ' | sed -r 's/\s+|\t+//g')
  return 0
}

# getField
# -- Set the return value to the value of the give variable in the DKIM signature.
# PARAMS: 1 = variable name
# RETURN CODES: "" = non-existent field, "[STRING]" = value of variable
# Example Usage: FIELD_VALUE=$(getField "d")
# ---- Returns the "d=" (domain) value from the DKIM Signature
function getField() {
  # DKIM Signature not defined? Leave with null response.
  [ -z "$DKIM_SIGNATURE" ] && return 0

  RETVAL=$(echo "$DKIM_SIGNATURE" | grep -Poi "$1"'=.*?(;|$)' | sed -r 's/;//g')
  echo "${RETVAL:`expr ${#1} + 1`:`echo ${#RETVAL}`}"
}


# getPubkey
# -- Get the Signer's public key using their selector (s=) and their domain (d=).
# PARAMS: 1 = selector, 2 = domain
# RETURN CODES: 1 = No DNS TXT record for selector. 2 = No Pubkey field in the record.
function getPubkey() {
  local QUERY_STR="$1._domainkey.$2"
  SIGNER_PUBKEY=$(dig txt +short $QUERY_STR)
  [ -z "$SIGNER_PUBKEY" ] && return 1
  SIGNER_PUBKEY=$(echo "$SIGNER_PUBKEY" | sed -r 's/\\|\s+|\t+|\"//g' | grep -Poi 'p=.*?(;|$)')
  [ -z "$SIGNER_PUBKEY" ] && return 2

  # All is good! Strip off any possible semi-colons (especially at the end and rip off the 'p=' via substring.
  SIGNER_PUBKEY=$(echo "${SIGNER_PUBKEY:2:`echo ${#SIGNER_PUBKEY}`}" | sed -r 's/;//g')
  return 0
}

# getEmailSections
# -- Get the header and body sections of the raw email.
function getEmailSections() {
  local HEADERS_PARSED=
  cat $EMAIL_FILE | \
  while read -r line || [[ -n "$line" ]]; do
    if [ -z "$HEADERS_PARSED" ]; then
      # Echo is used here rather than printf so it doesn't break...
      local TEMPVAR=$(echo "$line" | xxd -ps)
      if [[ "$TEMPVAR" == "0d0a" || "$TEMPVAR" == "0a0d" ]]; then HEADERS_PARSED="TRUE"
      else echo "$line">>/tmp/dkim-verify-$$; fi
    else
      echo "$line">>/tmp/dkim-verify-$$-body
    fi
  done
  EMAIL_HEADERS=$(cat /tmp/dkim-verify-$$)
  EMAIL_BODY=$(cat /tmp/dkim-verify-$$-body)
#  echo "${TC_BLUE}EMAIL HEADERS${TC_NORMAL}:"
#  echo "$EMAIL_HEADERS"
#  echo -e "\n\n\n${TC_YELLOW}EMAIL BODY${TC_NORMAL}:\n${EMAIL_BODY}"
  rm /tmp/dkim-verify-$$ /tmp/dkim-verify-$$-body
}

# getSigCanon
# -- Get the canonicalization of the DKIM Signature. Set to defaults as necessary.
# -- If no canonicalization algorithm is specified by the Signer, the "simple" algorithm defaults for both header and body.
function getSigCanon() {
  local DKIM_CANON=$(getField "c")
  if [[ "$DKIM_CANON" =~ '/' ]]; then
    # Both are explicitly defined, get them.
    DKIM_CANON_HEADER=$(echo "$DKIM_CANON" | cut -d'/' -f1)
    DKIM_CANON_BODY=$(echo "$DKIM_CANON" | cut -d'/' -f2)
  elif [ -z "$DKIM_CANON" ]; then
    # No canon. specified, set to defaults (simple/simple).
    DKIM_CANON_HEADER="simple"
    DKIM_CANON_BODY="simple"
  else
    # No slash character, only one specification means that the header canon. is explicitly defined. Body is default.
    DKIM_CANON_HEADER="$DKIM_CANON"
    DKIM_CANON_BODY="simple"
  fi

  # If anything came out NOT simple or relaxed, set them to simple.
  if [[ "$DKIM_CANON_HEADER" != "simple" && "$DKIM_CANON_HEADER" != "relaxed" ]]; then DKIM_CANON_HEADER="simple"; fi
  if [[ "$DKIM_CANON_BODY" != "simple" && "$DKIM_CANON_BODY" != "relaxed" ]]; then DKIM_CANON_BODY="simple"; fi
}

# canonicalizeHeader
# -- Canonicalize the header of the email (EMAIL_HEADERS) in accordance with the (DKIM_CANON_HEADER) algorithm.
function canonicalizeHeader() {
  CANON_HEADERS=
  if [[ "$DKIM_CANON_HEADER" == "simple" ]]; then
    # RFC 6376, S 3.4.1:
    # The "simple" header canonicalization algorithm does not change header
    #  fields in any way.  Header fields MUST be presented to the signing or
    #  verification algorithm exactly as they are in the message being
    #  signed or verified.  In particular, header field names MUST NOT be
    #  case folded and whitespace MUST NOT be changed.
    CANON_HEADERS="${EMAIL_HEADERS}"
  elif [[ "$DKIM_CANON_HEADER" == "relaxed" ]]; then
    # RFC 6376, S 3.4.2:
    # The "relaxed" header canonicalization algorithm MUST apply the following steps in order:
    #  + Convert all header field names (not the header field values) to
    #    lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
    local TEMP_OUT=/tmp/dkim-verify-$$
    [ -f "$TEMP_OUT" ] && rm $TEMP_OUT
    echo "${EMAIL_HEADERS}" | \
    while read -r line || [[ -n "$line" ]]; do
      local HEADER=$(echo "$line" | cut -d':' -f1 | tr '[:upper:]' '[:lower:]')
      local CUT_TEST=$(echo "$line" | cut -d':' -f2 | tr '[:upper:]' '[:lower:]')
      if [[ "${HEADER}" == "${CUT_TEST}" ]]; then
        echo -ne "${line}\r\n" >>$TEMP_OUT
        continue
      fi
      LANG='' line=$(echo "$line" | sed -r 's/^[\x21-\x7E]+://')
      line=$(echo "${HEADER}:${line}" | sed -r 's/\x0a|\x0d//g')
      echo -ne "${line}\r\n" >>$TEMP_OUT
    done
    CANON_HEADERS=$(cat $TEMP_OUT)
    rm $TEMP_OUT
#echo -e "CH1:\n${CANON_HEADERS}"
#echo "${CANON_HEADERS}" | xxd

    # Unfold all header field continuation lines as described in
    #  [RFC5322 S 2.2.3]; in particular, lines with terminators embedded in
    #  continued header field values (that is, CRLF sequences followed by
    #  WSP) MUST be interpreted without the CRLF.  Implementations MUST
    #  NOT remove the CRLF at the end of the header field value.
    # -- I'm going to try a slightly different approach to this, rather than intensive scanning.
    echo -n "${CANON_HEADERS}" | xxd -ps | tr '\n' ' ' | sed -r 's/\s+//g' | sed -r 's/(0d)+/0d/g' | sed -r 's/(0a)+/0a/g' \
      |  sed -r 's/(0[aAdD]){2}((20)+|(09)+)+//g' >$TEMP_OUT
    CANON_HEADERS=$(echo -n `cat $TEMP_OUT` | perl -pe 's/([0-9a-fA-F]{2})/chr hex $1/gie')

#echo -e "CH2:\n${CANON_HEADERS}"
#echo "${CANON_HEADERS}" | xxd

    # Convert all sequences of one or more WSP characters to a single SP
    #  character.  WSP characters here include those before and after a
    #  line folding boundary.
    #  Delete all WSP characters at the end of each unfolded header field
    #  value.
    CANON_HEADERS=$(echo -n "${CANON_HEADERS}" | sed -r 's/(\s+|\t+)+/ /g')
#echo -e "CH3:\n${CANON_HEADERS}"
#echo "${CANON_HEADERS}" | xxd
    
    # Delete any WSP characters remaining before and after the colon
    #  separating the header field name from the header field value.  The
    #  colon separator MUST be retained.
    # -- Easy, find the first : character, seek and spaces or tabs out and nuke them.
    echo -n "${CANON_HEADERS}" | sed -r 's/(\s|\t)*:(\s|\t)*/:/'

echo -e "\n${TC_CYAN}CANON_FINAL:\n${CANON_HEADERS}${TC_NORMAL}"
    rm $TEMP_OUT
  else
    # The given canonicalization header doesn't match either above. Default it. This shouldn't ever happen.
    CANON_HEADERS="${EMAIL_HEADERS}"
  fi
}

# canonicalizeBody
# -- Canonicalize the body of the email (EMAIL_BODY) in accordance with the (DKIM_CANON_BODY) algorithm.
function canonicalizeBody() {
  CANON_BODY=
  local TEMP_OUT=/tmp/dkim-verify-$$
  if [[ "$DKIM_BODY_CANON" == "relaxed" ]]; then
    echo
  else
    # Default to "simple".
    # RFC 6376, S 3.4.3
    # The "simple" body canonicalization algorithm ignores all empty lines
    #  at the end of the message body.  An empty line is a line of zero
    #  length after removal of the line terminator.  If there is no body or
    #  no trailing CRLF on the message body, a CRLF is added.  It makes no
    #  other changes to the message body.  In more formal terms, the
    #  "simple" body canonicalization algorithm converts "*CRLF" at the end
    #  of the body to a single "CRLF".
    echo -n "${EMAIL_BODY}" | xxd -ps | tr -d '\n' | tr -d '\r' | sed -r 's/\s+//g' >$TEMP_OUT
    printf "0d0a" >>$TEMP_OUT
    sed -r -i 's/((0d)+|(0a)+)+$/0d0a/' $TEMP_OUT
    CANON_BODY=$(echo -n `cat $TEMP_OUT` | perl -pe 's/([0-9a-fA-F]{2})/chr hex $1/gie')
  fi
  rm $TEMP_OUT
  echo "BODY_CANON: $CANON_BODY"
}




#########################################################
#########################################################
#########################################################
#########################################################
# BEGIN MAIN FUNCTION:


# Initialize Colors
colors
# Set up the environment with a clean slate (always just in case)
initialize

# Test given parameters...
[[ "$1" =~ '^--?h(elp)?$' ]] && usage
[ ! -f "$1" ] && errorOutput "Please provide a valid file!" 1
EMAIL_FILE="$1"
# Shift the filename parameter out of the way to process the OPTIONS field, if any.
shift


# Extract the DKIM Signature from the message.
echo " +++ Extracting DKIM-Signature from the message.."
extractSignature "${EMAIL_FILE}"
[ $? -eq 1 ] && errorOutput "Failed to find DKIM-Signature header, aborting!" 2


# Get the selector (s=) field and the domain (d=) field.
echo " +++ Acquiring the public RSA key used to sign the header."
DKIM_SELECTOR=$(getField "s")
DKIM_DOMAIN=$(getField "d")
getPubkey "$DKIM_SELECTOR" "$DKIM_DOMAIN"
if [ $? -eq 1 ]; then
  errorOutput "Failed to find public key for selector \"${DKIM_SELECTOR}\" at domain \"${DKIM_DOMAIN}\"." 3
elif [ $? -eq 2 ]; then
  errorOutput "Found TXT record, but no public key (p=), for selector \"${DKIM_SELECTOR}\" at domain \"${DKIM_DOMAIN}\"." 3
fi
echo "${TC_GREEN}PUBKEY${TC_NORMAL}: ${SIGNER_PUBKEY}"


# Split up the email into headers vs. body.
getEmailSections
echo "$EMAIL_HEADERS"


# Get the Canonicalization type and canonicalize.
echo " +++ Getting the canonicalization types and performing canonicalization..."
getSigCanon
echo "${TC_CYAN}CANONICALIZATION${TC_NORMAL}: ${DKIM_CANON_HEADER} (header)/${DKIM_CANON_BODY} (body)"
# Set up the CANON_HEADERS and CANON_BODY variables.
canonicalizeHeader
canonicalizeBody


# Interpret the Body Hash.
echo " +++ Interpreting and verifying the Body Hash (bh) field of the signature..."
DKIM_BODYHASH=$(getField "bh")
echo "BH: $DKIM_BODYHASH"
COMPUTED_HASH=$(echo -n "${CANON_BODY}" | sha256sum | cut -d' ' -f1 | perl -pe 's/([0-9a-fA-F]{2})/chr hex $1/gie' | tr -d '\n' | tr -d '\r' | base64)
echo "CH: $COMPUTED_HASH"

# Successful exit.
exit 0
