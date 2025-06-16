import argparse
import gzip
import json
import logging
import logging.handlers
import tempfile
import uuid
from datetime import datetime

import requests
import urllib3
from clint.textui import progress
from pymisp import MISPEvent, MISPObject, MISPOrganisation, PyMISP

from config import (
    distribution_level,
    filter_strategy,
    import_extra_data,
    import_filter,
    log_params,
    merge_strategy,
    misp_key,
    misp_url,
    misp_verifycert,
    path_to_mitre_json,
    publish,
    rst_api_key,
    rst_api_url,
)

urllib3.disable_warnings()


HEADERS = {"Accept": "application/json", "X-Api-Key": rst_api_key}

parser = argparse.ArgumentParser(
    description="MISP Connector for RST Threat Feed by RST Cloud"
)
parser.add_argument(
    "-l",
    "--loglevel",
    type=str,
    help="Select a logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
)
args = parser.parse_args()

logger = logging.getLogger("rst")
ch = logging.handlers.RotatingFileHandler(
    log_params["filename"],
    maxBytes=log_params["maxBytes"],
    backupCount=log_params["backupCount"],
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s [%(processName)s] [%(funcName)s]: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
ch.setFormatter(formatter)
logger.addHandler(ch)
valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
valid_merge_strategies = [
    "threat_by_day",
    "threat_by_month",
    "threat_by_year",
    "threat",
]
valid_filter_strategies = ["all", "recent", "only_new"]
valid_extra_values = ["false", "true", "False", "True", "1", "0"]

if args.loglevel is None:
    if log_params["level"] in valid_log_levels:
        logger.setLevel(getattr(logging, log_params["level"]))
    else:
        parser.error("Invalid log level")
else:
    if args.loglevel in valid_log_levels:
        logger.setLevel(getattr(logging, args.loglevel))
    else:
        parser.error("Invalid log level")

MERGE = "threat"
if merge_strategy and merge_strategy in valid_merge_strategies:
    MERGE = merge_strategy
else:
    parser.error("Invalid merge strategy")

FILTER = "recent"
if filter_strategy and filter_strategy in valid_filter_strategies:
    FILTER = filter_strategy
else:
    parser.error("Invalid filter strategy")

EXTRA = False
if type(import_extra_data) is bool:
    if import_extra_data:
        EXTRA = True
else:
    parser.error("Invalid import_extra_data")

misp = PyMISP(misp_url, misp_key, misp_verifycert)
mitre_ttps = {}


def load_json_data(file_path):
    with open(file_path, "r", encoding="UTF-8") as file:
        content = json.load(file)
    return content


def lookup_value(json_data, key):
    results = [
        item["value"]
        for item in json_data["values"]
        if key == item["meta"]["external_id"]
    ]
    return results[0]


def download_files():
    file_urls = import_filter["indicator_types"]
    content = {}
    for url in file_urls:
        logger.info("Downloading %s feed", url)
        content[url] = download_feed(f"{rst_api_url}{url}?type=json&date=latest")
    return content


def download_feed(feed_url):
    feed = []
    r = requests.get(feed_url, headers=HEADERS, stream=True, timeout=600)
    with tempfile.TemporaryFile() as f:
        total_length = int(r.headers.get("content-length"))
        for chunk in progress.bar(
            r.iter_content(chunk_size=1024),
            label=f"{feed_url} - ",
            expected_size=(total_length / 1024) + 1,
        ):
            if chunk:
                f.write(chunk)
                f.flush()
        f.seek(0)
        with gzip.open(f, "rt") as file:
            for line in file:
                # if the last line is empty or corrupted, then skip
                try:
                    feed.append(json.loads(line))
                except:
                    pass
    return feed


def check_if_event_exists(name):
    event_info = generate_event_info(name)
    result = misp.search(controller="events", eventinfo=event_info)
    if len(result) > 0:
        return True
    else:
        return False


def format_tag(name, value):
    return f'{name}="{value}"'


# Generates event.info for a MISP Event based on a seclected merge strategy
# for a given threat name
def generate_event_info(name):
    event_prefix = "[RST Cloud] Threat Feed"
    if MERGE == "threat_by_day":
        event_prefix = f"{event_prefix} {datetime.now().date().isoformat()}"
    elif MERGE == "threat_by_month":
        event_prefix = f"{event_prefix} {datetime.now().strftime('%Y-%m')}"
    elif MERGE == "threat_by_year":
        event_prefix = f"{event_prefix} {datetime.now().strftime('%Y')}"
    else:
        pass
    return f"{event_prefix}: {name}"


def check_for_hash(entry):
    if (
        "md5" in entry
        and len(entry["md5"]) > 0
        or "sha1" in entry
        and len(entry["sha1"]) > 0
        or "sha256" in entry
        and len(entry["sha256"]) > 0
    ):
        return True
    else:
        return False


def threat_tag_mapping(threat):
    # Dictionary mapping suffixes to MISP galaxy types and replacement rules
    gal = "misp-galaxy:"
    threat_mappings = {
        "_group": (
            f"{gal}threat-actor",
            lambda x: x.replace("_group", ""),
        ),
        "_actor": (
            f"{gal}threat-actor",
            lambda x: x.replace("_actor", ""),
        ),
        "_tool": (f"{gal}tool", lambda x: x.replace("_tool", "")),
        "_stealer": (f"{gal}stealer", lambda x: x.replace("_stealer", "")),
        "_backdoor": (f"{gal}backdoor", lambda x: x.replace("_backdoor", "")),
        "_ransomware": (
            f"{gal}ransomware",
            lambda x: x.replace("_ransomware", ""),
        ),
        "_miner": (f"{gal}cryptominers", lambda x: x.replace("_miner", "")),
        "_exploit": (f"{gal}exploit-kit", lambda x: x.replace("_exploit", "")),
        "_botnet": (f"{gal}botnet", lambda x: x.replace("_botnet", "")),
        "_rat": (f"{gal}rat", lambda x: x.replace("_rat", "")),
        "_campaign": (f"{gal}campaign", lambda x: x.replace("_campaign", "")),
        "_technique": (f"{gal}technique", lambda x: x.replace("_technique", "")),
        "_vuln": (f"{gal}vulnerability", lambda x: x.replace("_vuln", "")),
    }

    # Find matching suffix and apply corresponding mapping
    for suffix, (galaxy_type, transform_func) in threat_mappings.items():
        if threat.endswith(suffix):
            name = format_tag(galaxy_type, transform_func(threat))
            return name.replace("_", " ")

    # Default case
    name = format_tag(f"{gal}malware", threat)
    return name.replace("_", " ")


def add_ref_update_event(refs, misp_event, attr_object):
    for ref in refs:
        attr_object.add_attribute(
            "text", value=ref, comment="reference to the original source"
        )
    misp_event.add_object(attr_object)
    return misp_event


def bundle_misp_event(name, data):
    org = MISPOrganisation()
    org.name = "RST Cloud"
    org.uuid = "b170e410-0b7c-4ae0-a676-89564e7a6178"
    event = MISPEvent()
    event.info = generate_event_info(name)
    event.Orgc = org
    event.uuid = uuid.uuid5(
        uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), event.info
    )
    event.distribution = distribution_level
    event.timestamp = datetime.now()
    event_tag = threat_tag_mapping(name)
    if "rstcloud" not in event_tag:
        # tag using misp galaxy notation
        event.add_tag(event_tag)
        event.add_tag(format_tag("rstcloud:threat:name", name))
    else:
        # tag with rstcloud names for search consistency for all rst data
        event.add_tag(event_tag)
    event.analysis = 2  # 0=initial; 1=ongoing; 2=completed
    event.threat_level_id = 2  # 1 = high ; 2 = medium; 3 = low; 4 = undefined
    # Limited disclosure, restricted to participants’ organisation and its clients
    event.add_tag("tlp:amber")
    # add attributes to the new event
    for entry in data:
        fseen = datetime.fromtimestamp(entry["fseen"]).date()
        lseen = datetime.fromtimestamp(entry["lseen"]).date()
        attr_comment = ""
        ref = []
        to_ids_flag = False
        if FILTER != "all":
            if FILTER == "recent":
                if not (entry["collect"] - entry["lseen"]) == 0:
                    continue
            if FILTER == "only_new":
                if not (entry["collect"] - entry["fseen"]) == 0:
                    continue
        attr_tag = ["tlp:amber"]
        for threat in entry["threat"]:
            attr_tag.append(threat_tag_mapping(threat))
        for rsttag in entry["tags"]["str"]:
            attr_tag.append(format_tag("rstcloud:category:name", rsttag))

        attr_tag.append(format_tag("rstcloud:score:total", entry["score"]["total"]))

        if entry["fp"] and entry["fp"]["alarm"]:
            if entry["fp"]["alarm"] == "true":
                attr_tag.append('false-positive:risk="high"')
            elif entry["fp"]["alarm"] == "possible":
                attr_tag.append('false-positive:risk="medium"')
            elif entry["fp"]["alarm"] == "false":
                attr_tag.append('false-positive:risk="low"')
            else:
                attr_tag.append('false-positive:risk="cannot-be-judged"')

        if entry["fp"]["descr"]:
            attr_comment = str(entry["fp"]["descr"])
        if len(entry["cve"]) > 0 and entry["cve"]:
            for cve in entry["cve"]:
                attr_tag.append(threat_tag_mapping(cve.upper() + "_vuln"))
        if len(entry["ttp"]) > 0:
            for ttp_id in entry["ttp"]:
                try:
                    attr_tag.append(
                        format_tag(
                            "misp-galaxy:mitre-attack-pattern",
                            lookup_value(mitre_ttps, ttp_id.upper()),
                        )
                    )
                except Exception as ex:
                    logger.error(
                        "Error while looking up the MITRE tag %s: %s",
                        ttp_id.upper(),
                        ex,
                    )
        if len(entry["industry"]) > 0 and entry["industry"]:
            for industry in entry["industry"]:
                attr_tag.append(format_tag("misp-galaxy:sector", industry))

        if entry["src"] and entry["src"]["report"] and len(entry["src"]["report"]) > 0:
            # extract references
            ref = entry["src"]["report"].split(",")
            # remove duplicates
            ref = list(dict.fromkeys(ref))

        if "ip" in entry:
            # only process if it needs to be imported
            if entry["score"]["total"] > import_filter["score"]["ip"]:
                attr_object = MISPObject("ip-port")
                # check for detection if the score is high enough
                if entry["score"]["total"] > import_filter["setIDS"]["ip"]:
                    to_ids_flag = True
                attr_object.add_attribute(
                    "ip",
                    to_ids=to_ids_flag,
                    value=entry["ip"]["v4"],
                    first_seen=fseen,
                    last_seen=lseen,
                    Tag=attr_tag,
                    comment=attr_comment,
                )
                if "asn" in entry and "num" in entry["asn"] and entry["asn"]["num"]:
                    attr_object.add_attribute("AS", value=entry["asn"]["num"])
                    if EXTRA:
                        attr_object.add_attribute(
                            "text", value=str(entry["asn"]), disable_correlation=True
                        )
                if (
                    "geo" in entry
                    and "country" in entry["geo"]
                    and entry["geo"]["country"]
                ):
                    attr_object.add_attribute(
                        "country-code", value=entry["geo"]["country"]
                    )
                    if EXTRA:
                        attr_object.add_attribute(
                            "text", value=str(entry["geo"]), disable_correlation=True
                        )
                if (
                    "ports" in entry
                    and len(entry["ports"]) > 0
                    and entry["ports"][0] != -1
                ):
                    for port in entry["ports"]:
                        attr_object.add_attribute("dst-port", value=port)
                event = add_ref_update_event(ref, event, attr_object)
        if "domain" in entry:
            if entry["score"]["total"] > import_filter["score"]["domain"]:
                attr_object = MISPObject("domain-ip")
                if entry["score"]["total"] > import_filter["setIDS"]["domain"]:
                    to_ids_flag = True
                attr_object.add_attribute(
                    "domain",
                    to_ids=to_ids_flag,
                    value=entry["domain"],
                    first_seen=fseen,
                    last_seen=lseen,
                    Tag=attr_tag,
                    comment=attr_comment,
                )
                if (
                    "ports" in entry
                    and len(entry["ports"]) > 0
                    and entry["ports"][0] != -1
                ):
                    for port in entry["ports"]:
                        attr_object.add_attribute("port", value=port)
                if "resolved" in entry and "whois" in entry["resolved"]:
                    attr_object.add_attribute(
                        "text",
                        value=str(entry["resolved"]["whois"]),
                        comment="Whois Info",
                        disable_correlation=True,
                    )
                if "resolved" in entry and "ip" in entry["resolved"]:
                    if (
                        "a" in entry["resolved"]["ip"]
                        and len(entry["resolved"]["ip"]["a"]) > 0
                    ):
                        for resolved_a in entry["resolved"]["ip"]["a"]:
                            attr_object.add_attribute(
                                "ip",
                                to_ids=False,
                                value=resolved_a,
                                first_seen=fseen,
                                last_seen=lseen,
                                comment=f'DNS to IP result for {entry["domain"]}',
                            )
                    if (
                        "cname" in entry["resolved"]["ip"]
                        and len(entry["resolved"]["ip"]["cname"]) > 0
                    ):
                        for resolved_cname in entry["resolved"]["ip"]["cname"]:
                            attr_object.add_attribute(
                                "domain",
                                to_ids=False,
                                value=resolved_cname,
                                first_seen=fseen,
                                last_seen=lseen,
                                comment=f'a CNAME for DNS to IP result for {entry["domain"]}',
                            )
                    if (
                        "alias" in entry["resolved"]["ip"]
                        and len(entry["resolved"]["ip"]["alias"]) > 0
                    ):
                        for resolved_alias in entry["resolved"]["ip"]["alias"]:
                            attr_object.add_attribute(
                                "domain",
                                to_ids=False,
                                value=resolved_alias,
                                first_seen=fseen,
                                last_seen=lseen,
                                comment=f'an Alias for DNS to IP result for {entry["domain"]}',
                            )

                event = add_ref_update_event(ref, event, attr_object)
        if "url" in entry:
            if entry["score"]["total"] > import_filter["score"]["url"]:
                attr_object = MISPObject("url")
                if entry["score"]["total"] > import_filter["setIDS"]["url"]:
                    to_ids_flag = True
                attr_object.add_attribute(
                    "url",
                    to_ids=to_ids_flag,
                    value=entry["url"],
                    first_seen=fseen,
                    last_seen=lseen,
                    Tag=attr_tag,
                    comment=attr_comment,
                )
                if (
                    "resolved" in entry
                    and "status" in entry["resolved"]
                    and entry["resolved"]["status"] > 0
                ):
                    attr_object.add_attribute(
                        "text",
                        value=str(entry["resolved"]["status"]),
                        comment="HTTP Status of the URL",
                        disable_correlation=True,
                    )
                if "parsed" in entry:
                    u = entry["parsed"]
                    attr_object.add_attribute("scheme", value=str(u["schema"]))
                    attr_object.add_attribute(
                        "domain",
                        to_ids=False,
                        value=u["domain"],
                        first_seen=fseen,
                        last_seen=lseen,
                    )
                    attr_object.add_attribute("resource_path", value=str(u["path"]))
                    attr_object.add_attribute("query_string", value=str(u["params"]))
                event = add_ref_update_event(ref, event, attr_object)
        if check_for_hash(entry):
            if entry["score"]["total"] > import_filter["score"]["hash"]:
                if entry["score"]["total"] > import_filter["setIDS"]["hash"]:
                    to_ids_flag = True
                attr_object = MISPObject("file")
                if "filename" in entry and entry["filename"]:
                    for name in entry["filename"]:
                        attr_object.add_attribute(
                            "filename",
                            to_ids=to_ids_flag,
                            value=name,
                            first_seen=fseen,
                            last_seen=lseen,
                            Tag=attr_tag,
                            comment=attr_comment,
                        )
                if "md5" in entry and len(entry["md5"]) > 0:
                    attr_object.add_attribute(
                        "md5",
                        to_ids=to_ids_flag,
                        value=entry["md5"],
                        first_seen=fseen,
                        last_seen=lseen,
                        Tag=attr_tag,
                        comment=attr_comment,
                    )
                if "sha1" in entry and len(entry["sha1"]) > 0:
                    attr_object.add_attribute(
                        "sha1",
                        to_ids=to_ids_flag,
                        value=entry["sha1"],
                        first_seen=fseen,
                        last_seen=lseen,
                        Tag=attr_tag,
                        comment=attr_comment,
                    )
                if "sha256" in entry and len(entry["sha256"]) > 0:
                    attr_object.add_attribute(
                        "sha256",
                        to_ids=to_ids_flag,
                        value=entry["sha256"],
                        first_seen=fseen,
                        last_seen=lseen,
                        Tag=attr_tag,
                        comment=attr_comment,
                    )
                event = add_ref_update_event(ref, event, attr_object)
    logger.debug("Found %s objects", len(event.objects))
    return event


def create_misp_event(name, event_data):
    try:
        misp_event = bundle_misp_event(name, event_data)
        # add to the database and publish
        if len(misp_event.objects) > 0:
            misp_event = misp.add_event(misp_event, metadata=True)
            if publish:
                misp.publish(misp_event)
    except Exception as ex:
        logger.error("create_misp_event: %s", ex)


def update_misp_event(name, event_data):
    try:
        misp_event = bundle_misp_event(name, event_data)
        # update the event and publish
        if len(misp_event.objects) > 0:
            misp_event = misp.update_event(misp_event, metadata=True)
            if publish:
                misp.publish(misp_event)
    except Exception as ex:
        logger.error("create_misp_event: %s", ex)


def process_files(feed_data):
    logger.debug("Processing the feeds")
    # this to contain all indicators grouped by a threat name
    container_dict = {}

    for feed in feed_data:
        for indicator in feed_data[feed]:
            threats = indicator.get("threat", [])
            if threats:
                for threat in threats:
                    # actor, campaign, malware, tool
                    if not threat.endswith(("_technique", "_vuln")):
                        container_dict.setdefault(threat, []).append(indicator)
    logger.info("Found %s threats to be converted", len(container_dict))
    return container_dict


if __name__ == "__main__":
    mitre_ttps = load_json_data(path_to_mitre_json)
    files = download_files()
    processed_data = process_files(files)

    for threat_name in processed_data:
        logger.debug("Publishing an event for %s", threat_name)
        event_exists = check_if_event_exists(threat_name)
        if MERGE == "threat_by_day":
            if event_exists:
                logger.info(
                    "Skipping the event for %s to avoid duplication", threat_name
                )
            else:
                create_misp_event(threat_name, processed_data[threat_name])
        else:
            if event_exists:
                update_misp_event(threat_name, processed_data[threat_name])
            else:
                create_misp_event(threat_name, processed_data[threat_name])

    logger.info("Finished publishing MISP events")
