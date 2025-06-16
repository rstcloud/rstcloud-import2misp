#!/usr/bin/env python
# -*- coding: utf-8 -*-
rst_api_url = "https://api.rstcloud.net/v1/"
rst_api_key = "get_from_rstcloud"
misp_url = "https://127.0.0.1/"  # change to the URL of your MISP server
# The MISP auth key can be created on the MISP web interface
# under the section http://[your_misp]/auth_keys/index
misp_key = "create_in_your_misp"
misp_verifycert = False
misp_client_cert = ""

# Choose whether you want to update events that were created before:
# - True: Downloads reports and updates events that were previously fetched.
#         Useful for getting fixes or updates to recent reports if there are any issues.
# - False: Stops importing if an event for this report already exists.
update_events = True

# Set to True to fetch events only for the current day.
# Set to False to fetch recent reports, allowing updates to recently modified reports to be delivered.
exact_date = False

publish = True
log_params = {
    "level": "DEBUG",
    "filename": "misp_rh_uploader.log",
    "maxBytes": 1024 * 1024 * 10,
    "backupCount": 3,
}
