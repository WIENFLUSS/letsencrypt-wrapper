#!/usr/bin/env python
"""Let's Encrypt Wrapper

Usage:
    letsencrypt-wrapper.py [DOMAINNAME] [--dry-run] [--staging] [--verbose]
        [--config=<conf>] [--generate_stanzas] [--skip-on-completion]
        [--renew-anyway] [--list-certs]

    letsencrypt-wrapper.py -h | --help

Arguments:
    DOMAINNAME

Options:
    -h, --help                 Show this screen
    -l, --list-certs           List configured certificates
    --staging                  Use the letsencrypt staging environment instead
                               of production to circumvent being blocked.
                               This will create _staging certificates.
    -c, --config FILE          Supply a non-default configuration file
                               [default: config.json]
    -d, --dry-run              Do not execute commands
    -g, --generate_stanzas     Print the necessary stanzas for a new vhost
    -v, --verbose              Log more verbosely.
    -s, --skip-on-completion   Do not execute EXECUTE_ON_COMPLETION
                               (implied by -d)
    -r, --renew-anyway         Force renewal even if the certificate is not
                               deemed to be expired
"""

# Docopt is a library for parsing command line arguments
import docopt

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from datetime import timedelta
from email.mime.text import MIMEText
from time import sleep
from acmetinywrapper import *
import json
import logging
import os
import smtplib
import subprocess
import sys

__author__ = "Florian Cech", "Markus Pawlata"
__email__ = "cech@wienfluss.net", "pawlata@wienfluss.net"
__version__ = "0.4"


def verify_config(CONFIG):
    """Checks for intact configuration-file, exits if there is a parameter
    missing or wrong. Content of files given in configuration are not
    validated.
    """
    # List of config entries that must point to folders
    required_folders = ['CERT_DIR', 'CHALLENGE_FOLDER']
    # List of config entries that must point to files
    required_files = ['ACCOUNT_KEY', 'DOMAIN_KEY', 'CHAIN_CERT', 'ACME_TINY']
    # List of config entries that need to be set
    required_variables = (['MAX_RETRIES', 'RETRY_WAIT_SECS'] +
                          required_folders + required_files)

    for variable in required_variables:
        if variable not in CONFIG:
            logging.error("{} config entry is not set.".format(variable))
            sys.exit(1)

    for folder in required_folders:
        if not os.path.isdir(CONFIG[folder]):
            logging.error("{} config entry is not a directory: {}".format(
                folder, CONFIG[folder]))
            sys.exit(1)

    for file in required_files:
        if not os.path.isfile(CONFIG[file]):
            logging.error(
                '{} config entry is not a file: {}'.format(file, CONFIG[file]))
            sys.exit(1)


def on_success(CONFIG):
    # Skip on SKIP_ON_COMPLETION and DRY_RUN
    if (CONFIG['SKIP_ON_COMPLETION'] or
            'EXECUTE_ON_COMPLETION' not in CONFIG or
            not CONFIG['EXECUTE_ON_COMPLETION'] or
            CONFIG['DRY_RUN']):
        return ""

    try:
        proc = subprocess.Popen(
            CONFIG['EXECUTE_ON_COMPLETION'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = proc.communicate()
        if proc.returncode != 0:
            answer = "Running command '{}' failed with {}".format(
                " ".join(CONFIG['EXECUTE_ON_COMPLETION']), err)
            logging.error(answer)
        else:
            answer = "Command '{}' successfully executed.".format(
                " ".join(CONFIG['EXECUTE_ON_COMPLETION']))
            logging.debug(answer)
    except Exception as ex:
        answer = "Running command '{}' failed hard with {}".format(
            " ".join(CONFIG['EXECUTE_ON_COMPLETION']), ex)
        logging.error(answer)
    return answer


def send_log_mail(CONFIG, body):
    """Sends summary emails to SUMMARY_EMAIL_TO.
    SUMMARY_EMAIL_TO has to be a single email-address.
    """

    # Do not try to send mail if the config is incomplete
    if ('SUMMARY_EMAIL_TO' not in CONFIG or
            'SUMMARY_EMAIL_TO' not in CONFIG or
            'SMTP_SERVER' not in CONFIG or
            CONFIG['SKIP_ON_COMPLETION'] or
            CONFIG['DRY_RUN']):
        return

    logging.info("Sending log via email.")
    msg = MIMEText(body)
    msg['Subject'] = 'Let\'s Encrypt Summary for: {}'.format(
        datetime.now().strftime('%d.%m.%Y %H:%M'))
    msg['From'] = CONFIG['SUMMARY_EMAIL_FROM']
    msg['To'] = ", ".join(CONFIG['SUMMARY_EMAIL_TO'])

    # This SMTP-Server has to be accesible from the sender and to not
    # require authentication (which we do not provide)
    s = smtplib.SMTP(CONFIG['SMTP_SERVER'])
    s.sendmail(
        CONFIG['SUMMARY_EMAIL_FROM'],
        CONFIG['SUMMARY_EMAIL_TO'],
        msg.as_string())
    s.quit()


def get_queued_domains(CONFIG):
    domain_queue = {}

    if CONFIG['SELECTED_DOMAIN']:
        if CONFIG['SELECTED_DOMAIN'] not in CONFIG['ENABLED_DOMAINS']:
            return []

        domains = [CONFIG['SELECTED_DOMAIN']]
    elif 'ENABLED_DOMAINS' not in CONFIG:
        return []
    else:
        domains = CONFIG['ENABLED_DOMAINS'].keys()

    for domain in domains:
        crt_file = "{cert_dir}/{host}/{host}{staging}.crt".format(
            cert_dir=CONFIG['CERT_DIR'],
            host=CONFIG['ENABLED_DOMAINS'][domain]['hostname'],
            staging="_staging" if CONFIG['STAGING_ONLY'] else "")

        if (os.path.isfile(crt_file)):
            try:
                logging.debug("Found cert for {}".format(domain))
                cert = read_cert_from_file(CONFIG, crt_file)
                days = (cert.not_valid_after - datetime.now()).days
            except ValueError:
                logging.error("Cert for {} was unreadable".format(domain))
                domain_queue.update({domain: 0})
                continue
            logging.debug(
                ("This certificate will expire on: {} " +
                 "(in {} days).").format(
                    cert.not_valid_after.strftime("%d.%m.%Y"),
                    days))

            if (datetime.now() > cert.not_valid_after - timedelta(
                    days=CONFIG['DAYS_LEFT_BEFORE_RENEW'])):
                logging.debug("Certificate for {} needs renewal.".format(
                    domain))
                domain_queue.update({domain: days})
            elif CONFIG['RENEW_ANYWAY']:
                logging.info(
                    ("Certificate for {} does not need renewal. But " +
                     "--renew-anyway is set, so queuing it anyway.").format(
                        domain))
                domain_queue.update({domain: days})
            else:
                logging.debug("Certificate for {} is fine.".format(
                    domain))
        else:
            # Certificate not found, set it to expire it immediately
            logging.debug(
                "Certificate for {} needs renewal (not found).".format(domain))
            domain_queue.update({domain: 0})

    # Returns a list of domains, sorted by expire-date (soonest first)
    domain_queue = [k for (k, v) in sorted(
        domain_queue.iteritems(), key=lambda (k, v): v)]

    return domain_queue


def read_cert_from_file(CONFIG, crt):
    with open(crt) as cert_64:
        cert = x509.load_pem_x509_certificate(
            cert_64.read(), default_backend())
    return cert


def log_cert_list(CONFIG):
    domains_to_renew = []
    logging.info(
        "The minimum validity-length for automatic renewal is " +
        "set to {} days.".format(
            CONFIG['DAYS_LEFT_BEFORE_RENEW']))
    if not CONFIG['VERBOSE']:
        logging.info(("First digit: 'r' means 'renewal', 'n' " +
                      "means 'no action'."))
        logging.info(("The Next three digits are days of validity, then " +
                      "domain-name."))

    if 'ENABLED_DOMAINS' in CONFIG:
        domain = CONFIG['SELECTED_DOMAIN']

        # Single domain request
        if domain and domain in CONFIG['ENABLED_DOMAINS']:
            domains = [domain]

        # domains from config
        elif domain is None or domain == '' or domain == '*':
            domains = CONFIG['ENABLED_DOMAINS'].keys()

        # invalid domain given
        else:
            logging.error('Invalid domain given: {}'.format(domain))
            domains = []

    # No domains configured
    else:
        logging.error('No domains configured in config file"')

    for domain in domains:
        crt_file = "{cert_dir}/{host}/{host}{staging}.crt".format(
            cert_dir=CONFIG['CERT_DIR'],
            host=CONFIG['ENABLED_DOMAINS'][domain]['hostname'],
            staging="_staging" if CONFIG['STAGING_ONLY'] else "")

        if (os.path.isfile(crt_file)):
            try:
                cert = read_cert_from_file(CONFIG, crt_file)
                days = (cert.not_valid_after - datetime.now()).days
                if not CONFIG['VERBOSE']:
                    logging.info('{} {:03d} - {}'.format(
                        ("n" if days > CONFIG['DAYS_LEFT_BEFORE_RENEW']
                            else "r"),
                        days,
                        domain
                    ))
                else:
                    logging.info(
                        ("Certificate for '{}' expires on: {} (in {} " +
                         "days). This certificate would {}be automatically " +
                         "renewed.").format(
                            domain,
                            cert.not_valid_after.strftime("%d.%m.%Y"),
                            days,
                            ("not " if days > CONFIG['DAYS_LEFT_BEFORE_RENEW']
                                else "")))

                if days <= CONFIG['DAYS_LEFT_BEFORE_RENEW']:
                    domains_to_renew.append(domain)
            except ValueError:
                if not CONFIG['VERBOSE']:
                    logging.error("r {:03d} - {} (found, unreadable)".format(
                        0, domain))
                else:
                    logging.error(
                        "Certificate for '{}' wasn't readable.".format(domain))
                domains_to_renew.append(domain)
        else:
            if not CONFIG['VERBOSE']:
                    logging.warning("r {:03d} - {} (not found)".format(
                        0, domain))
            else:
                logging.warn("Certificate for '{}' not found.".format(domain))
            domains_to_renew.append(domain)

    logging.info('{} domains to renew. {} domains in total.'.format(
        len(domains_to_renew),
        len(domains)))


def main():

    print '\n** Let\'s Encrypt Wrapper **\n'

    try:
        # Parse arguments, use file docstring as a parameter definition
        arguments = docopt.docopt(__doc__)
        domain = arguments['DOMAINNAME']
        staging = arguments['--staging']
        dry_run = arguments['--dry-run']
        gen_stanzas = arguments['--generate_stanzas']
        config_filename = arguments['--config']
        verbose = arguments['--verbose']
        skip_on_completion = arguments['--skip-on-completion']
        renew_anyway = arguments['--renew-anyway']
        list_certs = arguments['--list-certs']

        if verbose:
            logging.basicConfig(
                format='%(asctime)s [%(levelname)7s] - %(message)s',
                level=logging.DEBUG)
        else:
            logging.basicConfig(
                format='[%(levelname)7s] - %(message)s',
                level=logging.INFO)

    # Handle invalid options
    except docopt.DocoptExit as e:
        print e.message
        sys.exit(1)

    # Load configuration file
    try:
        with open(config_filename) as config_file:
            CONFIG = json.load(config_file)
            CONFIG['SELECTED_DOMAIN'] = domain
            CONFIG['STAGING_ONLY'] = staging
            CONFIG['DRY_RUN'] = dry_run
            CONFIG['GENERATE_STANZAS'] = gen_stanzas
            CONFIG['VERBOSE'] = verbose
            CONFIG['SKIP_ON_COMPLETION'] = skip_on_completion
            CONFIG['RENEW_ANYWAY'] = renew_anyway
            CONFIG['LIST_CERTS'] = list_certs
            logging.debug('Config loaded from {}'.format(config_filename))
    except Exception as e:
        logging.error('Couldn\'t load config file: {}'.format(config_filename))
        print e.message
        sys.exit(1)

    # Verify the configuration values
    verify_config(CONFIG)

    # Check if no domains are configured
    if 'ENABLED_DOMAINS' not in CONFIG or len(CONFIG['ENABLED_DOMAINS']) < 1:
        logging.error('No domains configured in config file"')
        sys.exit(1)

    # List certificates
    if CONFIG['LIST_CERTS']:
        log_cert_list(CONFIG)
        sys.exit(0)

    # Generate domains that need renewal
    domains = get_queued_domains(CONFIG)

    # Single domain request
    if domain and domain in CONFIG['ENABLED_DOMAINS']:
        if domain not in domains:
            crt_file = "{cert_dir}/{host}/{host}{staging}.crt".format(
                cert_dir=CONFIG['CERT_DIR'],
                host=CONFIG['ENABLED_DOMAINS'][domain]['hostname'],
                staging="_staging" if CONFIG['STAGING_ONLY'] else "")

            cert = read_cert_from_file(CONFIG, crt_file)
            days = (cert.not_valid_after - datetime.now()).days
            logging.info(
                ("This certificate will expire on: {} " +
                 "(in {} days) and does not need renewal. " +
                 "To override use --renew-anyway.").format(
                    cert.not_valid_after.strftime("%d.%m.%Y"),
                    days))
            domains = []
    elif domain is None or domain == '' or domain == '*':
        # Preconfigured domains
        logging.info('Parsing all {} domain(s) in the config.'.format(
            len(CONFIG['ENABLED_DOMAINS'])))
        logging.info('{} domain(s) need creation or renewal.'.format(
            len(domains)))
    else:
        logging.error('Invalid domain given: {}'.format(domain))
        sys.exit(1)

    domains_todo = len(domains)
    domains_success = []
    domains_failed = []
    domains_attention = []

    # Main loop, process all eligble domains
    for dom in domains:
        trap = True
        escape = False
        interator = 0

        # Check if the maximum amount of renewals is reached
        if ('MAX_RENEW_PER_RUN' in CONFIG and
                len(domains_success) >= CONFIG['MAX_RENEW_PER_RUN']):
            logging.info(
                ('Added {} of {} to renew/create. Reached the ' +
                 'limit of {}.').format(
                    len(domains_success),
                    domains_todo,
                    CONFIG['MAX_RENEW_PER_RUN']
                ))
            break

        while trap:
            try:
                logging.info("Processing domain {}".format(dom))
                # Instantiate signing class
                at = ACMEtinywrapper(CONFIG, dom)
                # Create a sign request
                at.create_sign_request()
                # Sign the cert
                at.sign_cert()
                logging.info("Successfully processed domain {}".format(dom))
                if at.generate_stanzas():
                    domains_attention.append(dom)
                domains_success.append(dom)
                break  # trap = False
            except LetsEncryptRateLimitException as err:
                # If we get ratelimit error do not retry this domain
                domains_failed.append(dom)
                logging.error(
                    ('Rate Limit encountered while processing {}.' +
                     'Please note only renewals will succeed from this point.'
                     ).format(dom))
                break
            except LetsEncryptFatalException as err:
                # A fatal error will make us quit immediately
                domains_failed.append(dom)
                logging.fatal((
                    'Fatal error encountered while processing {}\n\t{}'
                ).format(dom, err))
                escape = True
                break
            except LetsEncryptGenericException as err:
                # Non-fatal errors will cause retries

                interator += 1
                if interator <= CONFIG['MAX_RETRIES']:
                    logging.error((
                        'Updating the certificate failed, waiting {} seconds' +
                        ' for retry ({}/{}).').format(
                            CONFIG['RETRY_WAIT_SECS'],
                            interator,
                            CONFIG['MAX_RETRIES']))
                    logging.error("Error was: {}".format(err.message))
                    sleep(CONFIG['RETRY_WAIT_SECS'])
                else:
                    domains_failed.append(dom)
                    logging.error(
                        'Exhausted all retries for {}, giving up.'.format(dom))
                    logging.error("Error was: {}".format(err.message))
                    break

        # If something blocking any signing to succeed happens, exit
        if escape:
            logging.info("Exiting processing.")
            break

        if ('WAIT_BETWEEN_REQUESTS' in CONFIG and
                CONFIG['WAIT_BETWEEN_REQUESTS'] > 0 and
                domains_todo > 1):
            logging.info('Waiting {} seconds to resume.'.format(
                CONFIG['WAIT_BETWEEN_REQUESTS']))
            sleep(CONFIG['WAIT_BETWEEN_REQUESTS'])

    # Log success or failure

    if domains_todo == 0:
        body = 'No domains needed updating.'
    elif domains_todo == 1:
        # Updating a single certificate
        if domains_success:
            body = 'Certificate update for {} succeeded.'.format(
                domains_success[0])
            body += '\n' + on_success(CONFIG)
        else:
            body = 'Certificate update for {} failed.'.format(
                domains_failed[0])
    else:
        # Updating multiple certificates
        if len(domains_failed) == 0:
            body = ('All processed certificates updated sucessfully. {} ' +
                    'updated.\n\n').format(len(domains_success))
            body += 'Updated:\n'
            for domain in domains_success:
                body += ' - {}\n'.format(domain)

            body += '\n' + on_success(CONFIG)
        elif len(domains_failed) and not len(domains_success):
            body = 'No certificate was updated. {} errors.'.format(
                len(domains_failed))
        else:
            body = ('Of {} queued domains, {} were processed, {} failed to ' +
                    'update.\n').format(
                        domains_todo,
                        len(domains_failed) + len(domains_success),
                        len(domains_failed))

            body += 'Updated:\n'
            for domain in domains_success:
                body += ' - {}\n'.format(domain)

            body += '\nFailed to update:\n'
            for domain in domains_failed:
                body += ' - {}\n'.format(domain)

            if domains_attention:
                body += '\nThese domains need updates to their vHost-conf:\n'
                for domain in domains_attention:
                    body += ' - {}\n'.format(domain)

                body += '\nRun this script with -g to generate full stanzas.\n'

            body += '\n' + on_success(CONFIG)

    logging.info(body)
    send_log_mail(CONFIG, body)


if __name__ == '__main__':
    main()
