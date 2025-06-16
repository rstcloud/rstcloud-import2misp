# MISP Scripts to Integrate with RST Cloud

These scripts facilitate the integration of two RST Cloud products with MISP (Malware Information Sharing Platform):

- **RST Report Hub**: A daily feed of parsed public threat research, including blogs, articles, and PDF reports.
- **RST Threat Feed**: A technical feed of enriched Indicators of Compromise (IoCs).

For a trial, contact RST Cloud at [trial@rstcloud.net](mailto:trial@rstcloud.net) or visit [https://www.rstcloud.com/#free-trial](https://www.rstcloud.com/#free-trial).

## RST Report Hub

The `rst_report_hub.py` script automates the daily download of threat reports from RST Report Hub into MISP. The RST Cloud engine collects and classifies blogs, articles, and PDF reports using a decision tree ML classifier to filter out irrelevant content. Only original research is aimed to be ingested, with duplicates excluded (e.g., rewritten articles on platforms like Dark Reading)  unless they provide additional findings (e.g., a Medium article with new IoCs).

Each report is analyzed to create a full STIX 2.1 graph with objects and relationships, which is then approximated into the MISP model, despite some degradation due to differences between STIX and MISP standards. Reports are created as separate MISP events, tagged appropriately and mapped to MISP galaxies where possible. Due to MISP's limited threat database and challenges with synonym mapping, some external names may not map perfectly without introducing noise. RST Cloud also can provide actors, campaigns, malware, and tools definitions as a separate Galaxy as a part of the **RST Threat Library** product.

Articles are translated into English from various languages (e.g., Chinese, Russian, Korean, Italian) and include a summary, key facts, and main ideas, which are attached as event descriptions and notes. A PDF copy of each article is archived and uploaded to MISP. Relationships are stored as tags and comments, and potentially noisy extracted indicators (e.g., Cloudflare IPs or hashes of legitimate files like powershell.exe) are ingested with the `to_ids` flag set to `False` to prevent false positives in detection systems.

![RST Report Hub events in MISP](/screenshot_report_overview.png)
![RST Report Hub attributes in MISP](/screenshot_report_attributes.png)

The script supports updating existing reports if corrections or additional IoCs are available, controlled by configuration settings. The API key allows for retrieving updated reports and accessing historical data as needed.

## RST Threat Feed

The `rst_threat_feed.py` script downloads IoCs from RST Threat Feed and imports them into MISP for analysis. Currently, only IoCs attributed to at least one threat are imported, as the feed contains approximately 250,000 unique IoCs daily. Importing all indicators is possible but may impact MISP performance in average deployments, so testing is recommended. Scoring guidance:

- **Score > 45**: Clients find suitable for threat detection.
- **Score > 55**: Clients find suitable for threat prevention.
- **Score 0–20**: Higher false positive risk, ok for threat hunting. See FP tags with descriptions

The script offers multiple event merge strategies and filtering options to balance data volume, MISP performance, and the capacity of your CTI team. By default, a distinct MISP event is created or updated for each threat name per month, resulting in approximately 50,000 events annually for threats like Akira, Azorult, Redline Stealer, Lockbit, Cobalt Strike, etc. Events can also be split by day for more granularity or merged by year or by threat for fewer, larger events.

Splitting by month also makes it easier to observe how malware infrastructure changes over time, using MISP correlation functions and the number of indicators (in this case, attributes in events,  which is a basic and somewhat naive but still useful method).

There are many unattributed indicators for categories such as scan, sshprobe, webattack, etc. These are not covered by this script. RST Cloud provides special APIs for native integration with WAFs and firewalls to block these types of noisy, incoming attacks, as detecting them can generate thousands of alerts that no one would realistically have time to triage. If you still want to have these ingested into MISP, feel free to reach out to us. We can provide an updated script tailored to your use case.

![RST Threat Feed attributes in MISP](/screenshot_attributes.png)
![RST Threat Feed events in MISP](/screenshot.png)

Schedule the script to run daily via cron between 1 AM and 3 AM UTC.

## Configuration

### Minimal Configuration

To get started, configure the following variables in the respective configuration files (`config.py` for RST Threat Feed and `config_rh.py` for RST Report Hub):

#### RST Threat Feed (`config.py`)

```python
rst_api_key = 'your_rst_cloud_api_key'  # Obtain from RST Cloud
misp_url = 'https://your_misp_server/'  # URL of your MISP server
misp_key = 'your_misp_auth_key'  # Generated in MISP under http://[your_misp]/auth_keys/index
```

#### RST Report Hub (`config_rh.py`)

```python
rst_api_url = "https://api.rstcloud.net/v1/"  # Default RST Cloud API URL
rst_api_key = 'your_rst_cloud_api_key'  # Obtain from RST Cloud
misp_url = 'https://your_misp_server/'  # URL of your MISP server
misp_key = 'your_misp_auth_key'  # Generated in MISP under http://[your_misp]/auth_keys/index
```

#### Choosing a Merge Strategy (RST Threat Feed)

Select a `merge_strategy` in `config.py` to control how MISP events are created:

1. **threat_by_year**: Groups indicators by threat name and year (~5,000 events/year, thousands of attributes per event). Recommended with `filter_strategy="recent"` to avoid duplicates.
2. **threat_by_month** (default): Groups by threat name and month (~8,500 events/year, fewer attributes per event). Recommended with `filter_strategy="recent"` or `"only_new"`.
3. **threat_by_day**: Groups by threat name and day (up to 365 events per threat annually). Recommended with `filter_strategy="recent"` or `"only_new"` to manage performance.
4. **threat**: Groups by threat name only (fewer, larger events that grow over time). Recommended with `filter_strategy="recent"` or `"only_new"`.

```python
merge_strategy = "threat_by_month"  # Choose from: threat_by_day, threat_by_month, threat_by_year, threat
```

#### Choosing a Filter Strategy (RST Threat Feed)

Select a `filter_strategy` in `config.py` to control which indicators are imported:

1. **all**: Imports all indicators meeting the `import_filter` thresholds.
2. **recent** (default): Imports indicators updated in the last 24 hours.
3. **only_new**: Imports indicators created in the last 24 hours.

```python
filter_strategy = "recent"  # Choose from: all, recent, only_new
```

#### Choosing Import Filters (RST Threat Feed)

Configure the `import_filter` in `config.py` to set minimum scores for importing IoCs and enabling detection (`to_ids=True`):

```python
import_filter = {
    "indicator_types": ["ip", "domain", "url", "hash"],  # Types of IoCs to import
    "score": {"ip": 20, "domain": 20, "url": 20, "hash": 20},  # Minimum score to import
    "setIDS": {"ip": 45, "domain": 45, "url": 45, "hash": 45},  # Minimum score for to_ids=True
}
```

### Advanced Configuration

#### RST Threat Feed (`config.py`)

- **Distribution Level**: Set the MISP event distribution level (0: Your Organisation Only, 1: This Community Only, 2: Connected Communities, 3: All, 4: Sharing Group, 5: Inherit Event).

```python
distribution_level = 0  # Default: Your Organisation Only
```

- **Publish Events**: Automatically publish events to MISP.

```python
publish = True  # Set to False to disable auto-publishing
```

- **Import Extra Data**: Include additional contextual data (e.g., WHOIS, ASN, geo-location) as text comments.

```python
import_extra_data = True  # Set to False to exclude extra data
```

- **MITRE ATT&CK Mapping**: Specify the path to the MITRE ATT&CK JSON file for TTP mapping.

```python
path_to_mitre_json = "mitre-attack-pattern.json"
```

- **Logging**: Configure logging parameters.

```python
log_params = {
    "level": "DEBUG",  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
    "filename": "misp_uploader.log",
    "maxBytes": 1024 * 1024 * 10,  # 10 MB
    "backupCount": 3,  # Number of backup log files
}
```

#### RST Report Hub (`config_rh.py`)

- **Update Events**: Control whether existing MISP events are updated with new report data.

```python
update_events = True  # Set to False to skip updating existing events
```

- **Exact Date**: Fetch reports only for the current day or allow updates to recent reports.

```python
exact_date = False  # Set to True to fetch only today's reports
```

- **Publish Events**: Automatically publish events to MISP.

```python
publish = True  # Set to False to disable auto-publishing
```

- **SSL Verification**: Enable or disable SSL certificate verification for MISP connections.

```python
misp_verifycert = False  # Set to True to enable SSL verification
```

- **Logging**: Configure logging parameters.

```python
log_params = {
    "level": "DEBUG",  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
    "filename": "misp_rh_uploader.log",
    "maxBytes": 1024 * 1024 * 10,  # 10 MB
    "backupCount": 3,  # Number of backup log files
}
```

#### Command-Line Arguments (RST Report Hub)

The `rst_report_hub.py` script can be executed manually using command-line arguments:

- `--start-date`: Specify the start date for downloading reports (format: `YYYYMMDD`).
- `--misp-url`: Override the MISP URL from `config_rh.py`.
- `--rst-url`: Override the RST API URL from `config_rh.py`.
- `--galaxies_as_tags`: Convert MISP galaxies to tags (`True` or `False`).
- `--update_events`: Override the `update_events` setting (`True` or `False`).
- `--exact_date`: Override the `exact_date` setting (`True` or `False`).
- `--custom_techniques`: Include custom techniques in STIX parsing (`True` or `False`).
- `--keep_tactics`: Retain MITRE tactics (e.g., TAxxxx) in STIX parsing (`True` or `False`).
- `-l/--loglevel`: Override the logging level (e.g., `DEBUG`, `INFO`).

Example:

```bash
python rst_report_hub.py --start-date 20250101 --loglevel INFO --exact_date True
```

## Usage

1. Install dependencies listed in the scripts (e.g., `pymisp`, `stix2`, `requests`, `clint`, `tldextract`).
2. Configure `config.py` and `config_rh.py` with your API keys and MISP settings.
3. Schedule the scripts to run daily using cron (e.g., 1 AM–3 AM UTC).
4. Monitor logs (`misp_uploader.log` for Threat Feed, `misp_rh_uploader.log` for Report Hub) for errors or issues.

## Notes

- Ensure your MISP instance is properly configured to handle the volume of data, especially for the Threat Feed with large event sizes.
- The RST Report Hub script transforms STIX 2.1 bundles into MISP events, with custom handling for threat actors, TTPs, and relationships to minimize data loss.
- For performance optimization, test different merge and filter strategies for the Threat Feed based on your organization's needs.
- The scripts include error handling and logging to facilitate troubleshooting.

For further assistance, contact RST Cloud support at [support@rstcloud.net](mailto:support@rstcloud.net).