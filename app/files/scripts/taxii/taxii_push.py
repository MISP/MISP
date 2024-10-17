"""
Read MISP JSON content from files in a directory, convert it to STIX, and
push the content to a TAXII server.
"""
import argparse
import logging
import logging.config
import sys
import taxii2client
import urllib.parse
from base64 import b64decode
from pathlib import Path
from requests.auth import HTTPBasicAuth

import importlib
MODULE_TO_DIRECTORY = {
    "stix2": "cti-python-stix2",
    "stix": "python-stix",
    "cybox": "python-cybox",
    "mixbox": "mixbox",
    "misp_stix_converter": "misp-stix",
    "maec": "python-maec",
}
_CURRENT_PATH = Path(__file__).resolve().parent
_CURRENT_PATH_IDX = 0
for module_name, dir_path in MODULE_TO_DIRECTORY.items():
    try:
        importlib.import_module(module_name)
    except ImportError:
        sys.path.insert(_CURRENT_PATH_IDX, str(_CURRENT_PATH / dir_path))
        _CURRENT_PATH_IDX += 1
import misp_stix_converter


# Name of the logger to use for this application
_LOGGER_NAME = "taxii_push"


# Surely no multi-byte encodings here, but better safe than sorry.
_TAXII_ENVELOPE_PREFIX = '{"objects":['.encode("utf-8")
_TAXII_ENVELOPE_SUFFIX = "]}".encode("utf-8")
_TAXII_ENVELOPE_COMMA = ",".encode("utf-8")


class FileProcessingError(Exception):
    """
    Instances represent an error encountered while processing a specific
    MISP JSON file.
    """
    def __init__(self, filepath, description):

        message = "{}: {}".format(
            filepath, description
        )

        super().__init__(message)

        self.filepath = filepath


def setup_logging(log_level=logging.WARNING):
    """
    Creates and applies a logging configuration.
    :param log_level: A logging level.  Defaults to warning.  May be the level
        value as an int, or its name as a string.  Strings are checked case-
        sensitively against registered level names.
    """

    # A simple made-up config.  Customize to taste.
    logging_config = {
        "version": 1,

        "formatters": {
            "simple_format": {
                "format": "%(name)s [%(levelname)s] %(message)s",
            }
        },

        "handlers": {
            "simple_stream": {
                "class": "logging.StreamHandler",
                "formatter": "simple_format"
            }
        },

        # We don't necessarily log via the root logger, but the logging records
        # propagate here anyway.  Its handlers will act as a catch-all for all
        # logging records.
        "root": {
            "level": log_level,
            "handlers": ["simple_stream"]
        },

        # Maybe we let existing loggers continue to work, e.g. anything used
        # by dependency libraries?
        "disable_existing_loggers": False
    }

    logging.config.dictConfig(logging_config)


def parse_args():
    """
    Configure expected commandline parameters and process them.
    """
    parser = argparse.ArgumentParser(
        description="Translate MISP content to STIX 2.1 and push it to a TAXII"
                    " 2.1 server.",
        epilog="This tool reads all files from the given directory and assumes"
               " they contain JSON, not just those named as *.json."
    )

    parser.add_argument(
        "--dir",
        help="A directory with files containing JSON MISP events.",
        type=Path,
        required=True
    )

    parser.add_argument(
        "--baseurl",
        help="The base URL of the TAII 2.1 server",
        required=True
    )

    parser.add_argument(
        "--api_root",
        help="The API root of the TAXII 2.1 server to use",
        required=True
    )

    parser.add_argument(
        "--collection",
        help="The collection ID of the TAXII 2.1 server to push content to",
        required=True
    )

    parser.add_argument(
        "--log_level",
        help="Set logging verbosity level.  Default: %(default)s",
        choices=[
            "fatal",
            "error",
            "warning",
            "info",
            "debug"
        ],
        default="warning"
    )

    parser.add_argument(
        '--key',
        help='Base64 encoded auth'
    )
    args = parser.parse_args()

    return args


def api_root_from_collection_url(collection_id):
    """
    Strip path components off the end of the path portion of the given TAXII
    collection URL, to obtain the API root URL.  A TAXII collection URL path
    ought to have the form:

        <api_root>/collections/<collection_uuid>/

    So we want to strip off the last two components.  Only the very simplest
    sanity check is done on the given URL path.

    :param collection_url: A TAXII collection URL.
    :return: The API root URL, or None if it could not be found.
    """
    collection_url_parts = urllib.parse.urlparse(collection_url)

    # The "collections/<collection_uuid>/" part ought to have a fixed length,
    # since all UUID's have a fixed length (36 chars).  And
    # len("collections") == 11.
    #
    # The URL paths are supposed to end with "/", but be robust if they don't.
    if collection_url_parts.path.endswith("/"):
        suffix_size = 49
    else:
        suffix_size = 48

    if len(collection_url_parts.path) < suffix_size:
        api_root_url = None

    else:
        api_root_path = collection_url_parts.path[:-suffix_size]

        api_root_url_parts = collection_url_parts[:2] \
            + (api_root_path,) + \
            collection_url_parts[3:]

        api_root_url = urllib.parse.urlunparse(api_root_url_parts)

    return api_root_url


def log_status_failures(status):
    """
    Log some failure information from a TAXII status resource.
    :param status: A Status resource object of the taxii2-client library with
        a non-zero failure count.
    """
    log = logging.getLogger(_LOGGER_NAME)

    log.error(
        "The TAXII server failed to process some objects (%d failures%s)!",
        status.failure_count,
        # Be clear about whether processing has completed at this
        # point or not.
        " so far" if status.status == "pending" else ""
    )

    # If there are a large number of objects, there could be a large number of
    # failures.  Let's log failure messages at a more verbose logging level.
    if log.isEnabledFor(logging.DEBUG):
        for failure_details in status.failures:
            log.debug(
                "%s/%s: %s",
                failure_details["id"],
                failure_details["version"],
                # "message" property is optional
                failure_details.get("message", "")
            )


def push_taxii_envelope(taxii_collection, taxii_envelope_bytes):
    """
    Post the given TAXII envelope to the given collection.
    :param taxii_collection: A taxii2client Collection instance
    :param taxii_envelope_bytes: A bytes/bytearray object containing the TAXII
        envelope payload for the request
    """

    # Maybe taxii2client should have been written to accept bytearrays...
    if isinstance(taxii_envelope_bytes, bytearray):
        taxii_envelope_bytes = bytes(taxii_envelope_bytes)

    # Shall we wait for completion, or just fire-and-forget?  Maybe waiting
    # would take too long.  Note that even if we choose not to wait for
    # completion, it's a server implementation detail whether any asynchronous
    # processing is actually done.  It may always process all objects before
    # returning anyway.
    status = taxii_collection.add_objects(
        taxii_envelope_bytes,
        wait_for_completion=False
    )

    # We will get an immediate TAXII status resource even if not waiting for
    # completion.  It may simply say that the adds are still pending and not
    # give us much more information.  But it may also indicate some failures.
    # If we know of any failures at this point, let's log that.
    if status.failure_count:
        log_status_failures(status)


def make_taxii_envelopes(stix_objects, max_content_length):
    """
    Generate TAXII envelopes containing the given STIX objects, such that
    no envelope size exceeds max_content_length.  The envelopes generated
    will be bytearrays, and max_content_length is a byte count.
    :param stix_objects: An iterable of stix objects, where each stix object
        is an instance of a registered stix2 library class (it needs a
        serialize() method to produce JSON).
    :param max_content_length: The max TAXII envelope size, in bytes
    """
    log = logging.getLogger(_LOGGER_NAME)

    taxii_envelope_bytes = bytearray(_TAXII_ENVELOPE_PREFIX)

    # This won't force us to consume an object on every loop iteration.
    # I think the code might be a bit simpler this way...
    stix_objects = iter(stix_objects)  # ensure we have an iterator
    stix_object = next(stix_objects, None)

    # in a TAXII envelope, should we add a comma before a new object?
    first_in_envelope = True

    while stix_object:

        stix_object_json = stix_object.serialize()
        stix_object_json_bytes = stix_object_json.encode("utf-8")

        # resulting envelope size if we were to add this object and close the
        # envelope.
        new_envelope_len = len(taxii_envelope_bytes) \
            + len(stix_object_json_bytes) \
            + len(_TAXII_ENVELOPE_SUFFIX)

        if not first_in_envelope:
            new_envelope_len += len(_TAXII_ENVELOPE_COMMA)

        if new_envelope_len > max_content_length:
            # New envelope would be too large.  If we are on the first object,
            # we have a problem.  We have a single STIX object which is so
            # large it can't be posted to the server!  Maybe we just skip that
            # one and continue?
            if first_in_envelope:
                log.error(
                    "STIX object %s is too large to be posted to the TAXII"
                    " server!  Object size: %d, TAXII envelope size: %d,"
                    " API root max content length: %d bytes",
                    stix_object["id"],
                    len(stix_object_json_bytes),
                    new_envelope_len,
                    max_content_length
                )

                stix_object = next(stix_objects, None)

            else:
                # Yield our current envelope and start a fresh one.
                taxii_envelope_bytes += _TAXII_ENVELOPE_SUFFIX

                yield taxii_envelope_bytes

                taxii_envelope_bytes.clear()
                taxii_envelope_bytes += _TAXII_ENVELOPE_PREFIX
                first_in_envelope = True
                # ... and we will not consume stix_object.  It can be
                # checked for size as normal on the next iteration.  This
                # is where not forcing us to consume the object helps us
                # out.  It will be re-serialized though...

        else:
            # We can fit another object in the TAXII envelope without
            # exceeding the limit.
            if not first_in_envelope:
                taxii_envelope_bytes += _TAXII_ENVELOPE_COMMA

            taxii_envelope_bytes += stix_object_json_bytes
            first_in_envelope = False

            stix_object = next(stix_objects, None)

    # Push any remaining objects
    if not first_in_envelope:
        taxii_envelope_bytes += _TAXII_ENVELOPE_SUFFIX
        yield taxii_envelope_bytes


def convert_misp_file(misp_file):
    """
    Convert the given MISP file to STIX 2.1.
    :param misp_file: A path to a file with a MISP event in it.  May be
        a string or a pathlib path object.
    :return: A STIX 2.1 bundle object
    """
    log = logging.getLogger(_LOGGER_NAME)

    converter = misp_stix_converter.MISPtoSTIX21Parser()
    converter.parse_json_content(str(misp_file))

    # Log conversion warnings as warnings; errors as errors?
    if log.isEnabledFor(logging.WARNING):
        for id_, messages in converter.warnings.items():
            for message in messages:
                log.warning("STIX conversion: %s: %s", id_, message)

    if log.isEnabledFor(logging.ERROR):
        for id_, messages in converter.errors.items():
            for message in messages:
                log.error("STIX conversion: %s: %s", id_, message)

    return converter.bundle


def convert_misp_dir(content_dir):
    """
    Convert all MISP files in the given directory to STIX 2.1, and generate
    each converted STIX object one at a time.
    :param content_dir: The directory to process for MISP content.
    """
    log = logging.getLogger(_LOGGER_NAME)

    for event_file in content_dir.iterdir():
        try:

            if event_file.is_file():
                log.info("Processing: %s", event_file)

                stix_bundle = convert_misp_file(event_file)

                yield from stix_bundle.objects

        except Exception as e:
            # Wrap errors occurring with a specific file with an exception
            # type which tracks the file name.  It hopefully makes for
            # better error messages.
            raise FileProcessingError(event_file, str(e)) from e


def parse_auth(api_key):
    return HTTPBasicAuth(*b64decode(api_key.encode()).split(b':'))


def push_content(content_dir, baseurl, api_root, collection_url, api_key):
    """
    Push MISP content from files in the given directory, to a TAXII 2.1 server.
    This will translate each MISP event to STIX 2.1.
    :param content_dir: A directory with JSON files containing MISP content.
    :param collection_url: A TAXII 2.1 collection URL
    """

    log = logging.getLogger(_LOGGER_NAME)

    auth = parse_auth(api_key)

    #api_root_url = api_root_from_collection_url(collection_url)
    api_root_url = baseurl + "/" + api_root
    if not api_root_url:
        raise ValueError(
            "Could not compute API root URL from: " + collection_url
        )

    with taxii2client.ApiRoot(api_root_url, auth=auth) as api_root:
        max_content_length = api_root.max_content_length

    log.debug(
        "max content length for API root %s: %d",
        api_root_url, max_content_length
    )

    all_stix_objects = convert_misp_dir(content_dir)
    collection_url = api_root_url + '/collections/' + collection_url
    with taxii2client.Collection(collection_url, auth=auth) as taxii_collection:

        for taxii_envelope_bytes in make_taxii_envelopes(
                all_stix_objects, max_content_length
        ):
            push_taxii_envelope(taxii_collection, taxii_envelope_bytes)


def main():
    args = parse_args()

    setup_logging(args.log_level.upper())
    log = logging.getLogger(_LOGGER_NAME)

    try:
        push_content(args.dir, args.baseurl, args.api_root, args.collection, args.key)

    except Exception:
        log.fatal(
            "An error occurred!", exc_info=True
        )
        exit_status = 1

    else:
        exit_status = 0

    return exit_status


if __name__ == "__main__":
    sys.exit(main())
