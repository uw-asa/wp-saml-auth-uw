# wp-saml-auth-uw
Customization of pantheon-systems/wp-saml-auth to use multisite and assign roles by group without the need for configuration


## Certificates
It is acceptable for SAML Service Providers to use long-lived, self-signed certificates. 
Generate a private key and certificate pair with:

    openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -keyout sp.key -out sp.crt

## Service Provider Configuration
See _Network Admin->Settings->WP SAML Auth UW_ for your EntityID and corresponding ACS URLs. 
Add this info, and your certificate, to the Service Provider Registry.

Required attributes are: uwNetID, email, cn, and the gws_groups covering the group stems necessary for user roles.
Optional attributes are: uwStudentSystemKey.

## User Roles
See _Network Admin->Settings->WP SAML Auth UW_ for the UW group corresponding to the network's Super Admins.
For each subsite, see _Users->UW User Roles_ for the UW groups corresponding to that site, one for each role.
You probably want to give each site's admins the ability to manage all the groups in that stem.

It is possible that this plugin's sitename detection code will fail, and thus generate nonsensical or conflicting UW Group names.
If that happens, file a bug and we'll try to fix it asap.
