#!/usr/bin/env python
import os
import sys
import logging
import shutil
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

__author__ = "Florian Cech", "Markus Pawlata"
__email__ = "cech@wienfluss.net", "pawlata@wienfluss.net"
__version__ = "0.4"


class ACMEtinywrapper:
    """
    A convienence class to provide extra-functionality when working
    with Let's Encrypt. This uses cryptography for creating csrs.
    Also relies on acme-tiny for communication with the acme-api.
    See also: https://github.com/diafygi/acme-tiny
    """

    conf = None
    domain = None
    cert_directory = None
    crt_file = None
    vhost_file = None

    def __init__(self, CONFIG, domain):

        self.conf = CONFIG
        self.name = domain
        self.domain = CONFIG['ENABLED_DOMAINS'][self.name]['hostname']
        self.domain_info = self.conf['ENABLED_DOMAINS'][self.name]

        # This is dirty but allows to import acme-tiny, which is not a module
        sys.path.append(os.path.dirname(os.path.abspath(CONFIG['ACME_TINY'])))

        self.cert_directory = "{}{}".format(self.conf['CERT_DIR'], self.domain)
        self.crt_file = "{}/{}.crt".format(self.cert_directory, self.domain)

        if 'vhost_file' in self.domain_info:
            if os.path.isfile(self.domain_info['vhost_file']):
                self.vhost_file = self.domain_info['vhost_file']
                logging.debug('Vhost-file is located at {}'.format(
                    self.vhost_file))
            else:
                logging.error(('vHost read from configuration does not ' +
                               'exists: {}'.format(
                                   self.domain_info['vhost_file'])))
        else:
            logging.debug('No vhost-file given.')

        if self.conf['VERBOSE']:
            logging.basicConfig(
                format='%(asctime)s [%(levelname)5s] - %(message)s',
                level=logging.DEBUG)
        else:
            logging.basicConfig(
                format='%(asctime)s [%(levelname)5s] - %(message)s',
                level=logging.INFO)
            if self.conf['DRY_RUN']:
                logging.info(
                    "Dry run requested, no commands will be executed.")

        logging.debug(
            'Instantiating Domain Manager Class for {}'.format(domain))
        logging.debug(
            'Domain-Cert-Directory is located at {}'.format(
                self.cert_directory))

    def create_sign_request(self):
        """
        Uses cryptography to create a certificate signing request (csr)-
        """

        logging.info('Creating CSR for domain {}'.format(self.domain))

        self.csr_file = "{}/{}.csr".format(self.cert_directory, self.domain)

        # make sure that directory exists
        if not os.path.isdir(self.conf['CERT_DIR']):
            os.mkdir(self.conf['CERT_DIR'])
        if not os.path.isdir(self.conf['CERT_DIR'] + self.domain):
            os.mkdir(self.conf['CERT_DIR'] + self.domain)

        if not self.conf['DRY_RUN']:
            logging.debug('Creating a CSR for {}'.format(self.domain))

            with open(self.conf['DOMAIN_KEY'], 'r') as key_file:
                key = serialization.load_pem_private_key(
                    key_file.read(), None, default_backend())

            if 'aliases' in self.domain_info:
                aliases = [self.domain] + self.domain_info['aliases']
            else:
                aliases = []

            csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name([
                    # x509.NameAttribute(NameOID.COUNTRY_NAME, u"AT"),
                    # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u" "),
                    # x509.NameAttribute(NameOID.LOCALITY_NAME, u" "),
                    # x509.NameAttribute(NameOID.ORGANIZATION_NAME, u" "),
                    x509.NameAttribute(NameOID.COMMON_NAME, self.domain),
                ])).add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(alias) for alias in aliases]
                ),
                critical=False,
            )
            # Sign the CSR with our private key.
            csr = csr.sign(key, hashes.SHA256(), default_backend())
            with open(self.csr_file, 'w') as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))

        else:
            logging.debug("Dry-Run requested, command not executed!")

    def sign_cert(self):
        """
        Sign a certificate for the given domain and csr file
        """

        import acme_tiny

        self.cert_directory = "{}{}".format(self.conf['CERT_DIR'], self.domain)

        sign_args = [
            sys.executable,
            self.conf["ACME_TINY"],
            '--account-key',
            self.conf["ACCOUNT_KEY"],
            '--csr',
            self.csr_file,
            '--acme-dir',
            self.conf["CHALLENGE_FOLDER"]
        ]

        if self.conf['STAGING_ONLY']:
            sign_args += ["--ca", self.conf["STAGING_CA"]]

        logging.debug(
            ('Requesting signed certificate for {} with the equivalent for ' +
             'the following command:\n\t$ {}').format(
                self.domain, " ".join(sign_args)))

        if not self.conf['DRY_RUN']:
            # if we are doing a real run, create a backup for writing new crt
            if (os.path.exists(self.crt_file) and
                    not os.path.exists(self.crt_file + '_backup') and
                    not self.conf['STAGING_ONLY']):
                shutil.copyfile(self.crt_file, self.crt_file + '_backup')

            # Do not override crts with staging_only crts
            if self.conf['STAGING_ONLY']:
                crt = "{}/{}_staging.crt".format(
                    self.cert_directory, self.domain)
            else:
                crt = "{}/{}.crt".format(
                    self.cert_directory, self.domain)

            # Handoff to acme-tiny
            try:
                if self.conf['STAGING_ONLY']:
                    cert = acme_tiny.get_crt(
                        self.conf["ACCOUNT_KEY"],
                        self.csr_file,
                        self.conf["CHALLENGE_FOLDER"],
                        CA=self.conf["STAGING_CA"]
                    )
                else:
                    cert = acme_tiny.get_crt(
                        self.conf["ACCOUNT_KEY"],
                        self.csr_file,
                        self.conf["CHALLENGE_FOLDER"]
                    )

                # Write the actual cert-file
                with open(crt, 'w') as cert_file:
                    cert_file.write(cert)
                    # If there is an intermediate/chain cert, append it
                    # This is necessary for nginx and does not hurt apache-uses
                    if os.path.exists(self.conf['CHAIN_CERT']):
                        fp = open(self.conf['CHAIN_CERT'], 'r')
                        intermediate = fp.read()
                        cert_file.write(intermediate)
                        fp.close()

            except IOError as err:
                logging.debug("Error: Permission denied: " + err.filename)
                raise LetsEncryptFatalException(
                    "Could not write into the acme-challange " +
                    "folder (rerun with -v for debug information)")
            except Exception as err:
                logging.debug("Error: " + err.message)
                if 'urn:acme:error:rateLimited' in err.message:
                    raise LetsEncryptRateLimitException(
                        "Rate Limit encountered")
                elif 'Wrote file to' in err.message:
                    raise LetsEncryptFatalException(
                        "Acme-challange folder was not accessible from " +
                        "the web (rerun with -v for debug information)")
                else:
                    raise LetsEncryptGenericException(
                        "Certificate Signing Error:\n\t{}".format(err))

                # If we were successful, remove the backup crt
                if os.path.exists(self.crt_file + '_backup'):
                    os.remove(self.crt_file + '_backup')
        else:
            logging.debug("Dry-Run requested, command not executed!")

    def generate_stanzas(self):
        apache_vhost_template = ""
        needs_update = False

        if (self.vhost_file and
            "SSLCertificateFile      {}".format(
                self.crt_file) not in open(self.vhost_file).read()):
            apache_vhost_template += """
    Apache vhost config file {vhost_file} doesn't seem to contain the right \
SSL-Stanza.\n"""
            needs_update = True

        if not self.conf['GENERATE_STANZAS'] and not needs_update:
            return needs_update

        apache_vhost_template += """
    To finish the process, ensure that the vhost file for {domain} contains \
the following stanza:

        SSLCertificateFile      {crt_file}
        SSLCertificateKeyFile   {key_file}
        SSLCertificateChainFile {chain_file}

    Restart Apache after the changes have been made \
(this will interrupt service):

        (root):~ $ systemctl restart apache2.service

        """

        print apache_vhost_template.format(
            domain=self.domain,
            crt_file=self.crt_file,
            key_file=self.conf["DOMAIN_KEY"],
            chain_file=self.conf['CHAIN_CERT'],
            vhost_file=self.vhost_file
        )
        return needs_update


class LetsEncryptGenericException(Exception):
    pass


class LetsEncryptFatalException(
        LetsEncryptGenericException):
    pass


class LetsEncryptRateLimitException(
        LetsEncryptFatalException):
    pass
