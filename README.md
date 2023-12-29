# rstcloud-import2misp
The provided script facilitates the daily download of IoCs from RST Cloud and imports them into MISP for comprehensive analysis. Currently, only attributed to at least one threat IoCs are imported as the number of unique IoCs in the [feed](https://www.rstcloud.com/rst-threat-feed/) is about 250K each day.

There are a couple of event merge strategies available and also a number of filtering options configurable to find the balance between the amount of data imported, MISP performance, and capacity of CTI team to consume data.

Each day, a distinct event is created or updated for each threat name. This results in a substantial number of events, such as 300 events for threats like Akira, Azorult, Redline Stealer, Lockbit, Cobalt Strike, and others on one day, followed by 350 events on the next day, and so forth. This approach ensures that there is an abundance of valuable indicators and contextual information for each IoC, which are integrated into MISP as tags (including custom tags and common MISP taxonomies).

![RST Cloud attributes in MISP](/screenshot_attributes.png)
![RST Cloud events in MISP](/screenshot.png)


Use cron to configure the script to run daily from 1 am to 3 am UTC.

To trial, please, contact us https://www.rstcloud.com/#free-trial

## Configuration
### Minimal
---

Obtain a key and populate the following variables in the file named config.py:

```
rst_api_key = 'a key received from RST Cloud'
misp_url = 'https://127.0.0.1/'
misp_key = 'a key generated in MISP'
```

Have a look at the *import_filter* in the file *config.py*. It allows to set a minimum score for each type of indicators to be pushed into MISP and also the minimum score required to be identified as actionable (to_ids=true)

Please choose a strategy how MISP events are filtered:
1) filter_strategy="all"
    * all indicators are imported that match the import filter threshold for each indicator type
2) filter_strategy="recent"
    * default option
    * only recent indicators (updated within last 24 hours) are imported that match the import filter threshold for each indicator type
3) filter_strategy="only_new"
    * only new indicators (created within last 24 hours) are imported


> Regardless of a strategy selected there is an additional filtering that is controlled via the advanced configuration options using that match the import filter thresholds for each indicator type (see [Advanced](#Advanced))


Please choose a strategy how MISP events are to be created:
1) merge_strategy="threat"
    * default option
    * all indicators are grouped by a threat name
    * events tend to become bigger and bigger over time
2) merge_strategy="threat_by_day"
    * all indicators are grouped by a threat name per day
    * events are smaller but there are more of them (the worst case scenario is 365 events per each malware a year)
    * MISP correlation function may be impacting query performance  

### Advanced
---
Redefine import_filter variable to control what IoCs to import:
- `indicator_types`: you can select from ip, domain, url, hash
- `score`: what RST Cloud's total score for an indicator is considered a minimum required fro the indicator to be imported into MISP. You can set it for each individual indicator type
- `setIDS`: what RST Cloud's total score for an indicator is considered a minimum required to be set with a flag IDS that usually is used in MISP for indicators you want to send for real-time detection or blocking

`publish = true` is used to automatically publish events. You will be getting info about hundreds of malware threats a day

MISP does not provide optimal storage options for certain types of contextual information, such as WHOIS data. Therefore, you can configure that these extra details are to be imported as text comments using the parameter `import_extra_data` = `True` or `False`.

The script now supports mapping of TTP tags into MITRE taxonomy in MISP. It is done via the usage of MITRE ATT&CK json file from MISP project [mitre-attack-pattern.json](https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json). To modify the path to that file, use the parameter: `path_to_mitre_json` = "mitre-attack-pattern.json"