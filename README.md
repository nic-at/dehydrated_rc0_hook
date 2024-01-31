# dehydrated_rc0_hook
Hook for Dehydrated to be used with Rcode0

# Configuration
The configuration is done via  rc0_conf.yaml
The script checks for an environment variable RCODE0_CONFIG_FILE to load the config from.
If the Environment - Variable is not set, the script uses rc0_conf.yaml with the path where the script lies in as backup

All that is needed is the correct token(s) from the my.rcodezero.at - Panel.

If the user is only bound to one account it is ok to just use the default - entry.
In case of multiple accounts it is necessary to setup a correct Token per domain.

# Debugging
The script comes with the possibility to enable debug-log.
You just have to set the DEBUG-Variable in Preparations Section from False to True
The Debug Log is written to the same directory where the script resides in

# General Stuff
The script has a hardcoded delay for 30 seconds after the dns txt record is added to rc0 to make sure
the record can propagate via anycast worldwide.

