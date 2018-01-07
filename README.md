# jgss based authentication

It is composed of two parts:
TokenCreation will create a token
TokenConsumption will read the token

Debug:

the classes within java.security will print debug messages to stderr through sun.security.util.Debug class

To print interesting messages:

-Djava.security.debug=gssloginconfig,logincontext,configfile,configparser

to print everything (very verbose): -Djava.security.debug=all

in order to make it work, you must add a keytab file for the client account, a keytab file for the server account,
Also, the bcsLogin.conf jaas file is split in two sections (for testing purposes):
bcsLogin.conf.client
bcsLogin.conf.server
They should be put together into a file bcsLogin.conf



