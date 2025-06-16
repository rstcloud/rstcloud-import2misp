import argparse
import base64
import json
import logging
import logging.handlers
import os
from datetime import datetime, timedelta, timezone
from typing import List, Union

import misp_stix_converter
import rstapi
import stix2
import tldextract
import urllib3
from misp_stix_converter.stix2misp import ExternalSTIX2toMISPParser
from pymisp import MISPEvent, MISPOrganisation, PyMISP

from config_rh import (
    exact_date,
    log_params,
    misp_key,
    misp_url,
    misp_verifycert,
    publish,
    rst_api_key,
    rst_api_url,
    update_events,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def str_to_bool(value):
    if isinstance(value, bool):
        return value
    if value.lower() in ("true", "t", "1", "yes", "y"):
        return True
    if value.lower() in ("false", "f", "0", "no", "n"):
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: '{value}'")


parser = argparse.ArgumentParser(description="MISP Connector for RST Report Hub by RST Cloud")
parser.add_argument("--start-date", action="store", dest="start_date", required=False)
parser.add_argument("--misp-url", action="store", dest="misp_url", default=misp_url)
parser.add_argument("--rst-url", action="store", dest="rst_url", default=rst_api_url)
parser.add_argument(
    "--galaxies_as_tags",
    action="store",
    dest="galaxies_as_tags",
    type=str_to_bool,
    default=False,
)

parser.add_argument(
    "--update_events",
    action="store",
    dest="update_events",
    type=str_to_bool,
    default=update_events,
)

parser.add_argument(
    "--exact_date",
    action="store",
    dest="exact_date",
    type=str_to_bool,
    default=exact_date,
)

parser.add_argument(
    "--custom_techniques",
    action="store",
    dest="custom_techniques",
    type=str_to_bool,
    default=True,
)

parser.add_argument(
    "--keep_tactics",
    action="store",
    dest="keep_tactics",
    type=str_to_bool,
    default=False,
)

parser.add_argument(
    "-l",
    "--loglevel",
    type=str,
    help="Select a logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
)


cmd_args = parser.parse_args()

RST_API_URL = os.environ.get("RST_API_URL") or cmd_args.rst_url
RST_API_KEY = os.environ.get("RST_API_KEY") or rst_api_key
RST_REPORT_DATE_FORMAT = "%Y%m%d"
RST_PDF_TEMP_DIR = os.environ.get("RST_PDF_TEMP_DIR", "./")
RST_CUSTOM_TTPS = cmd_args.custom_techniques
RST_KEEP_TACTICS = cmd_args.keep_tactics
RST_EXACT_DATE = cmd_args.exact_date

MISP_API_URL = os.environ.get("MISP_API_URL") or cmd_args.misp_url
MISP_API_KEY = os.environ.get("MISP_API_KEY") or misp_key
MISP_GALAXIES_AS_TAGS = cmd_args.galaxies_as_tags
MISP_UPDATE_EVENTS = cmd_args.update_events


if cmd_args.start_date is not None:
    START_DATE = datetime.strptime(cmd_args.start_date, RST_REPORT_DATE_FORMAT)
else:
    START_DATE = datetime.now(timezone.utc)

if MISP_API_KEY is None or RST_API_KEY is None:
    raise RuntimeError("Env MISP_API_KEY and RST_API_KEY must be set")


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

if cmd_args.loglevel is None:
    if log_params["level"] in valid_log_levels:
        logger.setLevel(getattr(logging, log_params["level"]))
    else:
        parser.error("Invalid log level")
else:
    if cmd_args.loglevel in valid_log_levels:
        logger.setLevel(getattr(logging, cmd_args.loglevel))
    else:
        parser.error("Invalid log level")

logger.info("Connecting to MISP")
misp_connector = PyMISP(url=MISP_API_URL, key=MISP_API_KEY, ssl=misp_verifycert)
logger.info("MISP Connected")
rst_connector = rstapi.reporthub(RST_API_KEY, RST_API_URL)


def create_date_range(start_date: datetime) -> List[datetime]:
    delta = timedelta(days=1)
    dates: List[datetime] = list()
    start_date = start_date.replace(tzinfo=timezone.utc)
    while start_date <= datetime.now(timezone.utc):
        dates.append(start_date)
        start_date += delta
    return dates


def format_tag(name, value):
    return f'{name}="{value}"'


def lookup_value(json_data, key):
    results = [
        item["value"]
        for item in json_data["values"]
        if key == item["meta"]["external_id"]
    ]
    return results[0]


def resolve_producer(creator_obj: dict, producers_list: list):
    """
    Resolves a normalized producer name from a creator object by matching its domain
    to known producers listed in a reference dataset (e.g., MISP database).

    This function:
    - Extracts the domain from the 'name' field in `creator_obj`, removing any subdomains.
    - Reconstructs the domain using only the registrable domain and public suffix (e.g., `example.com`, `example.com.au`).
    - Iterates over known producers to find a match using the cleaned domain against 'official-refs' URLs.
    - Returns the matched producer name from the dataset, or falls back to the normalized domain.

    Args:
        creator_obj (dict): A dictionary containing metadata about the source/creator.
                            Expected to include a 'name' key with a domain or URL-like string.
        producers_list (list): A list of dictionaries representing known producers.
                          Each producer may include 'meta' with 'official-refs' and a 'value'.

    Returns:
        str: The matched producer value from the `producers` list, or the normalized domain
             if no match is found.
    """
    # Extract and normalize the domain name from the creator's name field
    raw_name = creator_obj.get("name", "").lower()
    ext = tldextract.extract(raw_name)

    # Reconstruct domain: domain + suffix (e.g., "example.com", "example.com.au")
    producer = f"{ext.domain}.{ext.suffix}"

    # Match against known producers based on domain pattern in their official references
    for p in producers_list:
        official_refs = p.get("meta", {}).get("official-refs", [])
        for link in official_refs:
            if producer in link.lower():
                return p["value"]

    # Fallback to normalized domain if no producer match found
    return producer


def load_json_file(path):
    with open(path, "rb") as f:
        return json.load(f)


def resolve_country(country, countries):
    try:
        if "country" not in country:
            return None
        country_code = country.get("country").upper()
        for item in countries:
            if country_code == item.get("meta", {}).get("ISO", "").upper():
                return item["value"].capitalize()
    except Exception as e:
        logger.error("Error resolving country %s: %s", country, e)
        return None


def resolve_region(region, regions):
    try:
        if "region" not in region:
            return None
        region_name = region.get("region")
        for item in regions:
            if region_name.lower() == item.get("value", {}).split(" - ")[1].lower():
                return item["value"].capitalize()
    except Exception as e:
        logger.error("Error resolving region %s: %s", region, e)
        return None


def resolve_sector(sector, sectors):
    try:
        if sector.get("identity_class", "") != "class":
            return None
        sector_name = sector.get("name")
        for item in sectors:
            misp_sector = item.get("value", "").lower()
            misp_sector_synonyms = item.get("synonyms", [])
            rst_sector = sector_name.lower()
            if (
                rst_sector == misp_sector
                or misp_sector in rst_sector
                or rst_sector in misp_sector
            ):
                return item["value"].capitalize()
            elif len(misp_sector_synonyms) > 0:
                for syn in misp_sector_synonyms:
                    syn = syn.lower()
                    if rst_sector == syn or syn in rst_sector or rst_sector in syn:
                        return item["value"].capitalize()
    except Exception as e:
        logger.error("Error resolving sector %s: %s", sector, e)
        return None


def resolve_ttp(ttp, ttp_list):
    try:
        if "x_mitre_id" not in ttp:
            return None
        mitre_id = ttp.get("x_mitre_id").upper()
        if not mitre_id.startswith("TA"):
            for item in ttp_list:
                if mitre_id == item.get("meta", {}).get("external_id", "").upper():
                    return item["value"]
                elif (
                    mitre_id.split(".")[0]
                    == item.get("meta", {}).get("external_id", "").upper()
                ):
                    return item["value"]
    except Exception as e:
        logger.error("Error resolving TTP %s: %s", ttp, e)
        return None


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


def download_reports(start_date: datetime) -> Union[None, list]:
    formated_dt = start_date.strftime(RST_REPORT_DATE_FORMAT)
    logger.info("Downloading all reports for %s", formated_dt)
    response = rst_connector.GetReports(formated_dt)
    if isinstance(response, dict) and response.get("status", "") == "error":
        # 'Max retries reached'
        # 'No reports found'
        logger.error("Error: %s", response["message"])
        return None
    reports = []
    if RST_EXACT_DATE:
        report_date = START_DATE.strftime(RST_REPORT_DATE_FORMAT)
        for report in response:
            if report["id"].startswith(report_date):
                reports.append(report)
    else:
        reports = response
    return reports


def download_stix(report_id: str) -> Union[None, dict]:
    logger.info("Downloading STIX for report %s", report_id)
    response = rst_connector.GetReportSTIX(report_id)
    if isinstance(response, dict) and "status" in response:
        logger.error(response["message"])
        return None
    logger.info("Got %s for report %s", response["id"], report_id)
    return response


def download_pdf(report_id: str) -> Union[None, bytes]:
    logger.info("Downloading PDF for report %s", report_id)
    path = os.path.join(RST_PDF_TEMP_DIR, f"{report_id}.pdf")
    response = rst_connector.GetReportPDF(report_id, path)
    if isinstance(response, dict) and "error" in response:
        if response["status"] == "error":
            logger.error("Unable to fetch PDF for %s", report_id)
            return None
        if response["status"] == "ok":
            logger.info("Got %s.pdf", report_id["id"])
    return path


def delete_pdf(file_path: str):
    return os.remove(file_path)


def get_stix_from_dt_range(dates: List[datetime]) -> List[dict]:
    for dt in dates:
        reports = download_reports(dt)
        logger.info("Found %s reports", len(reports))
        if reports is None:
            logger.info("Skip %s No reports found", dt)
            continue
        # Access loaded JSON dictionaries:
        stix_parser = CustomSTIX2toMISPParser()
        logger.info("Initialising STIX parser")
        synonyms_mapping = stix_parser.synonyms_mapping
        new_mapping = {}
        # these synonyms are extra as they are not mapped by the Report Hub
        # excluded to avoid FP parsing on the MISP side
        ban = [
            "misp-galaxy:cmtmf-",
            "misp-galaxy:atrm=",
            "misp-galaxy:china-defence-universities=",
            "misp-galaxy:gsma-motif=",
            "misp-galaxy:surveillance-vendor=",
            "misp-galaxy:dwva=",
            "misp-galaxy:ammunitions=",
            "misp-galaxy:firearms",
            "misp-galaxy:intelligence-agency=",
            "misp-galaxy:nato=",
        ]
        for key, values in synonyms_mapping.items():
            new_values = []
            for value in values:
                match_ban = False
                for item in ban:
                    if item in value:
                        match_ban = True
                        break
                if match_ban:
                    continue
                else:
                    new_values.append(value)
            if len(new_values) > 0:
                new_mapping[key] = new_values
        stix_parser.synonyms_mapping = new_mapping
        for r in reports:
            report_id = r["id"]
            stix = download_stix(report_id)
            pdf_path = download_pdf(report_id)
            pdf_content = None
            if pdf_path is not None:
                with open(pdf_path, "rb") as f:
                    pdf_content = f.read()
            if stix is None:
                logger.info("Skip %s. No STIX found", report_id)
                continue
            upload_to_misp([stix], pdf_content, stix_parser)
            delete_pdf(pdf_path)
    return True


def attach_pdf_to_event(
    pdfevent: MISPEvent, pdf_content: bytes, report_id: str
) -> MISPEvent:
    attr_type = "attachment"
    value = f"{report_id}.pdf"
    data = base64.b64encode(pdf_content).decode("utf-8")
    comment = "Attached PDF copy of the report"
    pdfevent.add_attribute(type=attr_type, value=value, data=data, comment=comment)
    logger.info("PDF attached successfully")
    return pdfevent


def transform_stix(stix_bundle: dict, report_obj: dict):
    # takes a stix bundle and iterates over it. All intrusion sets are converted to threat actors.
    # all ids are updated including relationships and references
    # RST_CUSTOM_TTPS: custom techniques are removed if True
    # RST_KEEP_TACTICS: TA\d+ are removed if True
    names = []
    new_objets = []
    for obj in stix_bundle["objects"]:
        if obj["type"] == "intrusion-set":
            # Create a new threat actor object
            name = obj.get("name", "").replace("_", " ")
            threat_actor = {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": obj["id"].replace("intrusion-set", "threat-actor"),
                "name": name,
                "description": obj.get("description", ""),
                "aliases": obj.get("aliases", []),
                "created_by_ref": obj.get("created_by_ref"),
                "modified": obj.get("modified"),
                "created": obj.get("created"),
            }
            names.append({"name": name, "aliases": obj.get("aliases", [])})
            # add the new threat actor to the bundle
            new_objets.append(threat_actor)
            # Update relationships and references
            for rel in stix_bundle["objects"]:
                if rel["type"] == "relationship":
                    if rel["source_ref"] == obj["id"]:
                        rel["source_ref"] = threat_actor["id"]
                    if rel["target_ref"] == obj["id"]:
                        rel["target_ref"] = threat_actor["id"]
                if obj["id"] in rel.get("object_refs", []):
                    rel["object_refs"].append(threat_actor["id"])
                    rel["object_refs"].remove(obj["id"])
            # Replace the intrusion set with the new threat actor
            # objects_to_be_removed.remove(obj)
        elif obj["type"] in ["malware", "campaign", "tool"]:
            if obj["type"] == "tool":
                name = obj["name"] + "_tool"
            elif obj["type"] == "campaign":
                name = obj["name"] + "_campaign"
            else:
                name = obj["name"]
            # to map names to MISP dictionaries better
            keywords = [
                "stealer",
                "ransomware",
                "rat",
            ]
            obj["name"] = obj.get("name", "").replace("_", " ")
            if "aliases" in obj:
                found = False
                for alias in obj["aliases"]:
                    if found:
                        break
                    for keyword in keywords:
                        if alias.endswith(keyword):
                            name = alias.replace("_", " ")
                            found = True
                            break
            names.append({"name": name, "aliases": obj.get("aliases", [])})
            new_objets.append(obj)
        elif obj["type"] == "attack-pattern":
            if obj["name"].startswith("TA"):
                if RST_KEEP_TACTICS:
                    new_objets.append(obj)
            elif "aliases" in obj and len(obj["aliases"]) > 0:
                if RST_CUSTOM_TTPS and obj["aliases"][0].endswith("_technique"):
                    new_objets.append(obj)
            else:
                new_objets.append(obj)
        else:
            new_objets.append(obj)
        obj["object_marking_refs"] = [
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        ]
    stix_bundle["objects"] = new_objets

    new_labels = []
    for l in report_obj["labels"]:
        if l not in ["iocs_not_found", "iocs_found"]:
            new_labels.append(l.replace("_", " "))
    for item in names:
        found = False
        for label in report_obj["labels"]:
            if item["name"] == label:
                if len(item["aliases"]) > 0 and "_" in item["aliases"][0]:
                    new_labels.append(threat_tag_mapping(item["aliases"][0]))
                else:
                    new_labels.append(threat_tag_mapping(name))
                break
        if not found:
            if len(item["aliases"]) > 0 and "_" in item["aliases"][0]:
                new_labels.append(threat_tag_mapping(item["aliases"][0]))
            else:
                new_labels.append(threat_tag_mapping(name))

    report_obj["labels"] = new_labels
    return stix_bundle, report_obj


class CustomSTIX2toMISPParser(ExternalSTIX2toMISPParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__synonyms_mapping_override = None  # Custom override mapping

    @property
    def synonyms_mapping(self):
        if self.__synonyms_mapping_override is not None:
            return self.__synonyms_mapping_override
        return super().synonyms_mapping  # Fallback to base class behavior

    @synonyms_mapping.setter
    def synonyms_mapping(self, value):
        if not isinstance(value, dict):
            raise ValueError("synonyms_mapping must be a dictionary.")
        self.__synonyms_mapping_override = value


def convert_stix_bundle_to_misp_event(
    stix_bundle: dict, pdf_content: bytes, stix_parser: CustomSTIX2toMISPParser
) -> MISPEvent:
    # load MISP producers
    stix_parser_dir = os.path.dirname(misp_stix_converter.__file__)

    producer_file = "data/misp-galaxy/clusters/producer.json"
    producer_path = os.path.join(stix_parser_dir, producer_file)
    producers = load_json_file(producer_path).get("values", {})

    ttps_file = "data/misp-galaxy/clusters/mitre-attack-pattern.json"
    ttps_path = os.path.join(stix_parser_dir, ttps_file)
    ttps = load_json_file(ttps_path).get("values", {})

    countries_file = "data/misp-galaxy/clusters/country.json"
    countries_path = os.path.join(stix_parser_dir, countries_file)
    countries = load_json_file(countries_path).get("values", {})

    regions_file = "data/misp-galaxy/clusters/region.json"
    regions_path = os.path.join(stix_parser_dir, regions_file)
    regions = load_json_file(regions_path).get("values", {})

    sectors_file = "data/misp-galaxy/clusters/sector.json"
    sectors_path = os.path.join(stix_parser_dir, sectors_file)
    sectors = load_json_file(sectors_path).get("values", {})

    # Find the report object
    report_obj = next(
        (obj for obj in stix_bundle["objects"] if obj["type"] == "report"), None
    )
    stix_bundle, report_obj = transform_stix(stix_bundle, report_obj)
    creator_obj = next(
        (
            obj
            for obj in stix_bundle["objects"]
            if obj["type"] == "identity" and obj["id"] == report_obj["created_by_ref"]
        ),
        None,
    )
    if not report_obj:
        raise ValueError("No report object found in STIX bundle")
    if not creator_obj:
        raise ValueError("No creator object found in STIX bundle")

    # Create MISP Event using the tandard library
    bundle = stix2.parsing.dict_to_stix2(stix_bundle, allow_custom=True, version=None)

    ref = report_obj.get("external_references", [{}])[0]

    # map RST source names to MISP producer names (MISP producers list is very limited though)
    producer = resolve_producer(creator_obj, producers)

    stix_parser.load_stix_bundle(bundle)
    stix_parser.parse_stix_bundle(
        producer=producer, galaxies_as_tags=MISP_GALAXIES_AS_TAGS
    )

    misp_event = stix_parser.misp_event
    if not misp_event:
        raise ValueError("Failed to create MISP event from STIX bundle")

    # update MISP event with custom report details
    org = MISPOrganisation()
    org.name = "RST Cloud"
    org.uuid = "b170e410-0b7c-4ae0-a676-89564e7a6178"
    misp_event.Orgc = org
    misp_event.distribution = 0  # your organisation only
    misp_event.analysis = 2  # completed
    misp_event.info = report_obj.get("name", "STIX Report")
    misp_event.date = report_obj.get("published", datetime.now(timezone.utc))
    misp_event.add_tag("RST Report Hub")
    report_id = ref.get("external_id", "")
    misp_event.add_attribute(
        type="link",
        value=ref.get("url", ""),
        comment=f'{ref.get("source_name", "")}. ID: {report_id}',
    )
    if pdf_content:
        misp_event = attach_pdf_to_event(misp_event, pdf_content, report_id)

    # mapping of threat is done automatically via synonyms
    # this method may introduce incorrect mapping of RST data to MISP data as the synonyms are not ideal
    # for exmaple, Cuba will be mapped to country and to a ransomware family named Cuba

    # Convert and add objects
    observables = ["ipv4-addr", "domain-name", "url", "email"]
    stix_objects = {}
    rels = []
    for obj in stix_bundle["objects"]:
        # prepare data for rel mapping later
        if obj["type"] != "relationship":
            stix_objects[obj["id"]] = obj
        else:
            rels.append(obj)

        if obj["type"] == "vulnerability":
            name = obj.get("name", "")
            misp_event.add_attribute(
                type="vulnerability",
                value=name,
                category="External analysis",
                comment=obj.get("description", ""),
            )
            misp_event.add_tag(threat_tag_mapping(f"{name}_vuln"))
        elif obj["type"].lower() in observables:
            # unset to_ids Flag for indicators listed in the reports
            # but considered as noise or as False Positives
            for attr in misp_event.attributes:
                if obj["value"] == attr.value:
                    attr.to_ids = False
        elif obj["type"].lower() == "file":
            # files are special observables
            for attr in misp_event.attributes:
                for value in obj["hashes"].values():
                    if value == attr.value:
                        attr.to_ids = False

    if not MISP_GALAXIES_AS_TAGS:
        # map parameters manually. More control but less data is transformed
        # Index objects by id for relationship mapping
        attributes = misp_event.attributes
        observables = ["ipv4-addr", "domain-name", "url", "email", "file"]

        # populate TTPs, locations, and sectors to the report tags and attributes
        for key, value in stix_objects.items():
            if key.startswith("attack-pattern"):
                if "x_mitre_id" in value:
                    # MISP is not aware of subtechniques and not always up to date
                    # so, sometimes it will return None
                    threat_name = resolve_ttp(value, ttps)
                    if threat_name is None:
                        threat_name = value.get("name")
                        if threat_name.startswith("TA"):
                            ttp_format = "misp-galaxy:tactic"
                        else:
                            ttp_format = "misp-galaxy:technique"
                        misp_event.add_tag(format_tag(ttp_format, threat_name))
                    else:
                        ttp_format = "misp-galaxy:mitre-attack-pattern"
                        misp_event.add_tag(format_tag(ttp_format, threat_name))
                    continue
                else:
                    # custom techniques
                    threat_name = value.get("name")
                if threat_name and not threat_name.endswith("_technique"):
                    threat_name = threat_name + "_technique"
                misp_event.add_tag(threat_tag_mapping(threat_name))
            elif key.startswith("location"):
                if "country" in value:
                    country_name = resolve_country(value, countries)
                    country_format = "misp-galaxy:country"
                    if country_name is None:
                        country_name = value.get("name")
                        misp_event.add_tag(format_tag(country_format, country_name))
                    else:
                        misp_event.add_tag(format_tag(country_format, country_name))
                    value["x_translated_country"] = country_name
                elif "region" in value:
                    region_name = resolve_region(value, regions)
                    region_format = "misp-galaxy:region"
                    if region_name is None:
                        region_name = value.get("name")
                        misp_event.add_tag(format_tag(region_format, region_name))
                    else:
                        misp_event.add_tag(format_tag(region_format, region_name))
                    value["x_translated_region"] = region_name
            elif key.startswith("identity"):
                if "identity_class" in value and value["identity_class"] == "class":
                    sector_name = resolve_sector(value, sectors)
                    sector_format = "misp-galaxy:sector"
                    if sector_name is None:
                        sector_name = value.get("name")
                        misp_event.add_tag(format_tag(sector_format, sector_name))
                    else:
                        misp_event.add_tag(format_tag(sector_format, sector_name))
                    value["x_translated_sector"] = sector_name

        # iterate over attributes and add comments from relationships
        for rel in rels:
            if (
                rel.get("source_ref") in stix_objects
                and rel.get("target_ref") in stix_objects
            ):
                src_obj = stix_objects[rel["source_ref"]]
                tgt_obj = stix_objects[rel["target_ref"]]

                if tgt_obj.get("aliases"):
                    tgt_name = tgt_obj.get("aliases")[0]
                else:
                    tgt_name = tgt_obj.get("name")

                if src_obj.get("aliases"):
                    src_name = src_obj.get("aliases")[0]
                else:
                    src_name = src_obj.get("name")

                # add targeted countries to the report
                if (
                    tgt_obj["type"] == "location"
                    and rel.get("relationship_type", "") == "targets"
                ):
                    if "x_translated_country" in tgt_obj:
                        country_format = "misp-galaxy:target-information"
                        misp_event.add_tag(
                            format_tag(country_format, tgt_obj["x_translated_country"])
                        )

                # add tags to vulnerability objects to show what threats target them
                if (
                    tgt_obj["type"] == "vulnerability"
                    and rel.get("relationship_type", "") == "targets"
                ):
                    for attr in attributes:
                        if attr.value == tgt_obj.get("name"):
                            attr.add_tag(threat_tag_mapping(src_name))
                            previous = ""
                            src_type = src_obj.get("type").capitalize()
                            if hasattr(attr, "comment"):
                                previous = attr.comment
                            comment = (
                                f"{rel.get('relationship_type', '')} -> {tgt_name}"
                            )
                            attr.comment = (
                                f"{previous}{src_type} {src_name} -> {comment}\n"
                            )
                            break

                if src_obj["type"] in (observables + ["indicator"]):
                    # process indicators and observables
                    comment = f"{rel.get('relationship_type', '')} -> {tgt_name}"
                    for attr in attributes:
                        if attr.value == src_obj.get("name"):
                            attr.add_tag(threat_tag_mapping(tgt_name))
                            previous = ""
                            if hasattr(attr, "comment"):
                                previous = attr.comment
                            if src_obj["type"] == "indicator":
                                attr.comment = f"{previous}Indicator -> {comment}\n"
                            elif src_obj["type"] in observables:
                                attr.comment = f"{previous}Observable -> {comment}\n"
                            break
    return misp_event


def upload_to_misp(
    stix_reports: List[dict], pdf: bytes, stix_parser: CustomSTIX2toMISPParser
) -> None:

    for sr in stix_reports:
        bundle_id = sr["id"]
        event = convert_stix_bundle_to_misp_event(sr, pdf, stix_parser)
        logger.info("Uploading bundle %s to MISP", bundle_id)
        try:
            response = misp_connector.add_event(event, pythonify=True)
            if "errors" not in response:
                if publish:
                    misp_connector.publish(event)
                event_id = response.id
                event_uuid = response.uuid
                logger.info(
                    "Bundle %s uploaded. MISP Event ID: %s, Event UUID: %s",
                    bundle_id,
                    event_id,
                    event_uuid,
                )
            else:
                if MISP_UPDATE_EVENTS:
                    response = misp_connector.update_event(event, pythonify=True)
                    if "errors" not in response:
                        if publish:
                            misp_connector.publish(event)
                        event_id = response.id
                        event_uuid = response.uuid
                        logger.info(
                            "Bundle %s updated. MISP Event ID: %s, Event UUID: %s",
                            bundle_id,
                            event_id,
                            event_uuid,
                        )
                    else:
                        logger.error(
                            "Bundle %s update failed: %s", bundle_id, response["errors"]
                        )
                        continue
                else:
                    logger.error(
                        "Bundle %s upload failed: %s", bundle_id, response["errors"]
                    )
                    continue
        except Exception as e:
            if response is not None:
                logger.error("Failed to upload bundle %s to MISP: %s", bundle_id, e)
            raise e


if __name__ == "__main__":
    dates_range = create_date_range(START_DATE)
    finished = get_stix_from_dt_range(dates_range)
    if not finished:
        cur_date = START_DATE.strftime(RST_REPORT_DATE_FORMAT)
        logger.info("No reports found for %s", cur_date)
        dates_range = create_date_range(START_DATE - timedelta(days=1))
        reports_str = ",".join(
            [x.strftime(RST_REPORT_DATE_FORMAT) for x in dates_range]
        )
        logger.info("Downloading reports in range %s", reports_str)
        get_stix_from_dt_range(dates_range)

    logger.info("All reports uploaded")
