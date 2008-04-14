================================================================================
SslCat 0.2.1
Copyright ©2007-2008 Liam Kirton <liam@int3.ws>

15th March 2008
http://int3.ws/
================================================================================

=========
Overview:
=========

SslCat is a simple tool to allow console interaction with SSL enabled services
offered by a target system. SslCat can also accept incoming connections from SSL
enabled clients.

SslCat accepts either interactive or piped input, and allows the control of
supported protocols and maximum cipher strength.

=============
Certificates:
=============

For accepting incoming connections, SslCat requires a self-signed SSL certificate
that is correctly installed in the local machine certificate store.

-> Generating (Optional)

   To generate a new self-signed root certificate and SslCat certificate pair,
   run Makecert.bat (requires makecert.exe from Microsoft, part of the .NET
   Framework SDK). This also performs the necessary installation.

   Note that generation isn't necessary when existing certificates are imported.

-> Importing Existing

   To import an existing certificate pair (SslCatRoot.pfx and SslCat.pfx)
   into the local certificate store, run ImportPfx.vbs. This requires the
   Microsoft redistributable library Capicom.dll (included).

   Note that default SslCat.pfx and SslCat.pfx are supplied in \Certificates.

===========
Parameters:
===========

/Target:
--------

The /Target parameter may contain a single target IP address.

/Port:
------

The /Port parameter may contain a single port number.

/Ssl2 /Ssl3 /Tls1:
------------------

These parameters determine the protocols supported by each connection. Specify
one or more as required.

Default: /Ssl2 /Ssl3 /Tls1

/Cipher:
--------

The /Cipher parameter specifies the maximum cipher strength to support for
each enabled protocol.

Default: 0 (i.e. unrestricted).

/Listen:
---------

The /Listen parameter specifies that SslCat should listen for incoming
connections on the specified port.

/Verbose:
---------

The /Verbose parameter specifies that certificate and algorithm information
should be displayed upon successful connection.

=========
Examples:
=========

Interactive Client:
-------------------

SslCat.exe /Target 25.0.1.1 /Port 443

SslCat.exe /Target 25.0.1.1 /Port 443 /Ssl2 /Cipher 40 /Verbose

SslCat.exe /Target 25.0.1.1 /Port 443 /Ssl2 /Ssl3 /Cipher 128 /Verbose

SslCat.exe /Target 25.0.1.1 /Port 443 /Tls1 /Cipher 128 /Verbose

Interactive Server:
-------------------

SslCat.exe /Port 443 /Listen

SslCat.exe /Port 443 /Listen /Ssl2 /Cipher 40 /Verbose

Piped:
------

type Request.txt | SslCat.exe /Target 25.0.1.1 /Port 443
          
================================================================================
