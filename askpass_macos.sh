#!/usr/bin/env bash
osascript <<'APPLESCRIPT'
display dialog "sudo needs your password:" with title "Authentication" default answer "" buttons {"Cancel","OK"} default button "OK" with hidden answer
text returned of result
APPLESCRIPT