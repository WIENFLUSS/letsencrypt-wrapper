# letsencrypt-wrapper - Quickstart
Wrapper for Let's Encrypt certificate creation and management

About
-----

The letsencrypt-wrapper allows you to create or renew SSL certificates via
Let's Encrypt (using acme-tiny). You can either use it with crontab or manually
check or renew certificates.

When adding a new certificate, manual use of this script is advised. You may
find it useful to run the script with `--staging` to test your configuration
first (this will not affect Let's Encrypt's rate limit).

Please read further information on configuration and examples down below.
You may also see available command-line options by running the script with
`--help`.

If you do not know what SSL, [Let's Encrypt](https://letsencrypt.org/) or acme
are, this script is probably not for you. It is strongly recommended that you
are at least familiar with the underlying technology. This script just offers
some shortcuts and further functionality than acme-tiny offers on its own.

Naturally the user running this script needs write-access for the cert-folder
and read-access for the configuration and keys.

Requirements
------------

This script uses acme-tiny which can be retrieved via GitHub:
[https://github.com/diafygi/acme-tiny](https://github.com/diafygi/acme-tiny)
(commit daba51d is verified to work). Just as acme-tiny does, we invite you to
read the source-code of both acme-tiny and this script.

Required python packages:

* docopt: Pythonic command line arguments parser
* docopts: Shell interpreter for docopt
* cryptography: Python's cryptographic standard library


Setup
-----

1. Clone letsencrypt-wrapper

        $ git clone git@github.com:WIENFLUSS/letsencrypt-wrapper.git

2. Get acme-tiny from GitHub

        $ cd letsencrypt-wrapper
        $ git clone git@github.com:diafygi/acme-tiny.git

3. Requirements installation (virtualenv oder global)

        $ pip install -r requirements.txt

    or use a virtualenv see Development section


4. Create config

You can find a full sample of the configuration-file at `config.sample.json`.
Simply rename `config.sample.json` to `config.json` and adapt to your needs.
Please note that to make the script callable from any directory all (!) paths
in the config should be absolute.


Configuration File
------------------

The default configuration file is `config.json`. All information for processing
of domains and the reading and storing of keys and certs has to be defined in
the config. Therefore, if the config-file is missing or unreadable the script
exits.

The idea of using config-files is that you may have multiple different domains
with their own account- or domain-key and in possibly wildly different
locations. So you may create and use multiple configuration-files.


### General

* STAGING\_CA: The URL where the Let's Encrypt ACME-API will be queried
* CERT\_DIR: The directory where certs (and corresponding signature request will
  be saved)
* ACCOUNT\_KEY: The path to the Let's Encrypt account key
* DOMAIN\_KEY: The path to the Let's Encrypt domain key you which to sign your
  request with
* CHAIN\_CERT: The path to the Let's Encrypt chain certificate (only used for
  stanza-templates)
* CHALLENGE\_FOLDER: The writable (!) folder in you write challenges and which
  Let's Encrypt will query via the domain to sign
* ACME\_TINY: Path to the acme-tiny script (this is not interchangeable, as we
  customized the script)
* DAYS\_LEFT\_BEFORE\_RENEW: Days left of the valid period of a certificates
  before it will be renewed
* MAX\_RENEW\_PER\_RUN: The maximum number of certificates to create/renew on
  one run (useful if you run the script every week and do not want to run into
  rate-limits)
* MAX\_RETRIES: The number of times a failed signing attempt may be retried
  (useful for timeouts and server errors, useless if the acme-challenge is not
  written or read properly)
* RETRY\_WAIT\_SECS: The number of seconds the script will wait to try again
  after a failed signing-attempt
* WAIT\_BETWEEN\_REQUESTS: The number of seconds to wait between sending
  (non-failed) signing requests
* EXECUTE\_ON\_COMPLETION: The command to execute on completion, as an
  argument-separated list (see above)
* SMTP\_SERVER: The server to send emails from. This has to receive emails
  without authorization
* SUMMARY\_EMAIL\_TO: The email-address to send summaries to (only a single
  email-address may be given as string)
* SUMMARY\_EMAIL\_FROM: The email-address log-emails will be sent "from"
* ENABLED\_DOMAINS: The dict of enabled domains. If no domain is given to the
  script, all enabled domains will be updated.


### The Domain-Object

The dict in the `ENABLED_DOMAINS`-entry in the config file holds entries just like the following:

    "domain-main": {
        "hostname": "domain.com",
        "vhost_file": "/etc/apache2/sites-enabled/domain.conf",
        "aliases": [
            "www.domain.com"
        ]
    }

The key for this dict-entry is the name used in the script (does not have to
be the hostname).

* hostname: holds the name the certificate will be request for (and what will
  be tested against in the challenge).
* vhost\_file: is used for hinting and is *only read*. It checks the file given
  for the proper cert line (which is auto-generated into the `CERT_DIR`.
* aliases: holds a list of aliases to request for this certificate. Please note
  that you do not have to repeat the value of `hostname` here, it will be done
  automatically.


Adding a new domain
-------------------

We assume at this point that you have created a domain- and account-key
previous to adding a domain (if you have not done that please read
[acme-tiny's](https://github.com/diafygi/acme-tiny) documentation for
pointers).

Add a block like the following to `config.json` (in "ENABLED_DOMAINS", probably
including a comma before or after the new block):

    "newdomain.domain.com": {
        "hostname": "newdomain.domain.com",
        "vhost_file": "/etc/apache2/sites-enabled/newdomain.conf",
        "aliases": [
            "alias-to-newdomain.domain.com"
        ]
    }

vhost\_file is optional and will only help you determine if you already have the
right SSL-stanza in your apache-config. Run with `-g` to force generation of
stanzas.

Then run:

    $ python /usr/local/lib/letsencrypt/letsencrypt-wrapper.py -c /usr/local/lib/letsencrypt/config.json newdomain.domain.com

Or:

    $ cd /usr/local/lib/letsencrypt
    $ python letsencrypt-wrapper.py -c config.json newdomain.domain.com


Checking a certificate
----------------------

### Using letsencrypt-wrapper

Show certificate information for given domain:

    $ python /usr/local/lib/letsencrypt/letsencrypt-wrapper.py -c /usr/local/lib/letsencrypt/config.json -l newdomain.domain.com

To list all domains simply use:

    $ python /usr/local/lib/letsencrypt/letsencrypt-wrapper.py -c /usr/local/lib/letsencrypt/config.json -l

### Using openssl

    $ openssl x509 -in /etc/ssl/private/certs/www.domain.com/www.domain.com.crt -text -noout

To check a certificate signing request (csr):

    $ openssl req -in /etc/ssl/private/certs/www.domain.com/www.domain.com.csr -noout -text


Limitations
-----------

What this script will do:
 * report missing configuration and missing files set in the configuration
 * automate certificate creation, including certificate signing request (csr)
 * give information about currently locally saved certificates

 What this script will NOT do:
 * create domain- or account-keys for you
 * download the intermediate (Let's Encrypt) certificate
 * automate server configuration


Examples
--------

A normal update for www.domain.com:

    $ python letsencrypt-wrapper.py www.domain.com -c /usr/local/lib/letsencrypt/config.json

If you see errors and want to see more, you may want to use the `-v` verbose
flag:

    $ python letsencrypt-wrapper.py www.domain.com -c /usr/local/lib/letsencrypt/config.json -v

Dry-Run the letsencrypt script for domain "newdomain.domain.com"
(in `/usr/local/lib/letsencrypt/`):

    $ bin/python letsencrypt-wrapper.py newdomain.domain.com --staging -d -c config_development.json -g

* `--staging` use Let's Encrypt staging server to avoid being blocked for too
  many requests
* `-d` dry-run - showing us the commands, but not calling them
* `-c` use a non-default config file (instead of the default `config.json`)
* `-g` prints the necessary stanzas for the given domains after generating the
  certificates.


Development
-----------

Create a virtualenv and install dependencies:

    $ virtualenv . --no-site-packages
    $ bin/pip install -r requirements.txt

Run the script:

    $ bin/python letsencrypt-wrapper.py -c config_development.json helloworld.domain.com


Author
------

[WIENFLUSS information.design.solutions KG](https://www.wienfluss.net/)


Licence
-------

[CC-BY-NC-SA 3.0](https://creativecommons.org/licenses/by-nc-sa/3.0/)

