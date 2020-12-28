#!/usr/bin/env python3

"""PaperMC Update Tool

This program checks and updates to new version of PaperMC if it is
available for download.

usage: photoco.py [-h] -v version paper_jar
version:   Major version for Minecraft, ie: 1.16
paper_jar: paper.jar / paperclip.jar / Paper-<VERSION>.jar file location.
"""

import argparse
import hashlib
import sys

from bs4 import BeautifulSoup
from pathlib import Path
from urllib.request import Request, urlopen


# HTML Class to parse, mainly here in the event it changes.
HTML_CLASS = "md5sum"


class ArgumentError(Exception):
    """Raised if an invalid argument was attempted to be utilized."""
    pass


def main():
    args = get_args()

    local_paper = args.paper_jar.strip()
    if not local_paper or not Path(local_paper).is_file():
        sys.exit("Invalid 'paper.jar' provided.")

    paper_version = args.version.strip()
    if not paper_version:
        sys.exit("Invalid 'version' provided.")

    try:
        local_md5 = get_local_md5(local_paper)

        url = generate_url(paper_version, fingerprint=True)
        remote_md5 = get_remote_md5(url, HTML_CLASS)
    except ArgumentError as argerr:
        sys.exit(argerr)

    if local_md5 == remote_md5:
        print("No updates available.")
        sys.exit(0)


def generate_url(version, fingerprint=False):
    """Creates a URL to either download an updated PaperMC server or
    download a 'fingerprint'.

    A 'fingerprint' URL is later parsed for a md5sum.
    """
    if not version.strip():
        raise ArgumentError("Invalid 'version' argument provided.")

    # Add the supplied version to the URL.
    base_url = ("https://papermc.io/ci/job/Paper-"
                f"{version.strip()}"
                "/lastStableBuild/artifact/paperclip.jar")

    # If we need the 'fingerprint', add the extension.
    if fingerprint:
        return f"{base_url}/*fingerprint*/"

    return base_url


def get_local_md5(paper_file):
    """Check the md5sum of the locally provided PaperMC installation."""
    fname = paper_file.strip()
    if not fname or not Path(fname).is_file():
        raise ArgumentError("Bad 'paper.jar' provided, could not generate"
                            " md5sum.")

    # Generate the md5sum
    with open(fname, 'rb') as f:
        data = f.read()
        return hashlib.md5(data).hexdigest()


def get_remote_md5(url, htmlclass):
    """Check the most current md5sum by parsing a webpage."""
    if not url:
        raise ArgumentError("Bad URL provided.")
    if not htmlclass:
        raise ArgumentError("Bad HTML class provided.")

    req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})

    # Make our connection to the remote web page.
    try:
        webpage = urlopen(req)
        soup = BeautifulSoup(webpage, features="lxml")
        md5str = soup.body.find('div', attrs={'class' : htmlclass}).text
    except Exception as exc:
        raise exc

    # Validate we successfully parsed some information.
    if not md5str:
        return Exception("md5sum returned from URL was invalid.")

    # At the time of creation, returned string from parsing is similar to:
    #  'MD5: 4abf78f9f2381858db7b5efe3cfa1b3a'
    md5split = md5str.split()
    if len(md5split) == 2 and len(md5split[1]) == 32:
        return md5split[1]
    elif len(md5split[0]) != 32:
        return Exception("md5sum returned from URL was invalid.")

    # If PaperMC changes format and pos 0 in array is 32 characters long.
    return md5split[0]


def get_args():
    """Process the arguments passed to the application."""
    parser = argparse.ArgumentParser(
        description="Checks and downloads updates for PaperMC Minecraft servers.")

    # Location of the currently installed Paper*.jar
    parser.add_argument("paper_jar",
                        type=str,
                        help="location of installed PaperMC server executable")

    # Major version of Minecraft we are updating.
    parser.add_argument("-v",
                        metavar="version",
                        dest="version",
                        required=True,
                        type=str,
                        help="major minecraft version to check updates for,"
                        " example: '1.16'")
    return parser.parse_args()


if __name__ == "__main__":
    main()
