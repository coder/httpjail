#!/usr/bin/env bash

# Check if password file exists
if [[ -f "/tmp/askpass.txt" ]]; then
    # Read password from file
    cat "/tmp/askpass.txt"
else
    # Fall back to GUI dialog
    osascript <<'APPLESCRIPT'
display dialog "sudo needs your password:" with title "Authentication" default answer "" buttons {"Cancel","OK"} default button "OK" with hidden answer
text returned of result
APPLESCRIPT
fi