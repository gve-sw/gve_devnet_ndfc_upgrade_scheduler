"""
Copyright (c) 2024 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import logging
import os
import re
import sys
from datetime import datetime
from time import sleep

import requests
import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from dotenv import load_dotenv
from rich.logging import RichHandler
from schema import Or, Schema, SchemaError
from urllib3 import disable_warnings

# Disable urllib warnings
disable_warnings()

# Load environment variables
load_dotenv()
NDFC_HOST = os.getenv("NDFC_HOST")
NDFC_USER = os.getenv("NDFC_USER")
NDFC_PASS = os.getenv("NDFC_PASS")
NDFC_DOMAIN = os.getenv("NDFC_DOMAIN")
NDFC_API_KEY = os.getenv("NDFC_API_KEY")
NDFC_DEBUG = os.getenv("NDFC_DEBUG", "false")

# Set up logger
FORMAT = "%(message)s"
if NDFC_DEBUG.lower() == "true":
    logging.basicConfig(
        level="DEBUG",
        format=FORMAT,
        datefmt="[%X]",
        handlers=[RichHandler(markup=True)],
    )
else:
    logging.basicConfig(
        level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(markup=True)]
    )
log = logging.getLogger("rich")

# Session auth to NDFC can be done via API token, or if username / password provided then we can
# get an API token from NDFC with those credentials
AUTH_MODE = None
if NDFC_API_KEY is not None:
    log.info("Found API key, using API key for authentication")
    AUTH_MODE = "API"
elif NDFC_USER is not None and NDFC_PASS is not None and NDFC_DOMAIN is not None:
    log.info(
        "Found username and password, using username and password for authentication"
    )
    AUTH_MODE = "USERPASS"
else:
    log.error("[red]No authentication information found, exiting")
    exit(1)

# Base path for NDFC API calls
NDFC_PATH = f"https://{NDFC_HOST}/appcenter/cisco/ndfc/api/v1"

# Store loaded config
global config


def is_two_digit(d) -> int:
    """
    Validate int values to allow leading zeros
    """
    if re.match(r"^\d{2}$", d):
        return int(d)


# Schema to validate config file syntax
config_schema = Schema(
    {
        "schedule": {
            "year": int,
            "month": Or(int, is_two_digit),
            "day": Or(int, is_two_digit),
            "hour": Or(int, is_two_digit),
            "minute": Or(int, is_two_digit),
            "timezone": str,
        },
        "upgrade": {
            "policy": str,
            "stage-image": bool,
            "timeout": int,
        },
        "devices": [str],
    }
)


class NDFC:
    def __init__(self):
        self.AUTH_HEADERS = {"Content-Type": "application/json"}
        self.REQUEST_HEADERS = {
            "X-Nd-Apikey": NDFC_API_KEY,
            "X-Nd-Username": NDFC_USER,
        }
        self.session = requests.Session()
        self.ready_for_upgrade = False
        self.image_staged = False
        self.validated = False
        self.upgrades_completed = False
        self.target_devices = config["devices"]

    def getAuthToken(self):
        """
        Log in & get authentication token
        """
        auth_body = {
            "userName": NDFC_USER,
            "userPasswd": NDFC_PASS,
            "domain": NDFC_DOMAIN,
        }

        # Send auth request
        url = f"https://{NDFC_HOST}/login"
        response = self.session.post(
            url, headers=self.AUTH_HEADERS, json=auth_body, verify=False
        )
        if response.status_code != 200:
            log.error("[red]Failed to get authentication token")
            sys.exit(1)
        else:
            log.info("[green]Successfully authenticated to NDFC")

        # Store auth headers for future requests
        self.REQUEST_HEADERS = {
            "X-Nd-Apikey": response.json()["token"],
            "X-Nd-Username": NDFC_USER,
        }

    def getNDFCVersion(self):
        """
        Validate current version of NDFC
        """
        url = f"{NDFC_PATH}/fm/about/version"
        response = self.session.get(url, headers=self.REQUEST_HEADERS, verify=False)
        if response.status_code != 200:
            log.error("[red]Error retrieving NDFC version:")
            log.error(f"[red]{response.text}")
            log.error("[red]Script will continue, but may not work as expected")
            return
        self.ndfc_version = response.json()["version"]
        log.info(f"NDFC Version: {self.ndfc_version}")
        if self.ndfc_version != "12.1.2e":
            log.error("[red]NDFC version must be 12.1.2e")
            log.error("[red]Script cannot continue. Exiting...")
            sys.exit(1)

    def getDeviceInfo(self, silent=False):
        """
        Query NDFC for device info that will be needed for later API calls
        """
        if not silent:
            log.info("Querying NDFC for device information...")

        url = f"{NDFC_PATH}/imagemanagement/rest/packagemgnt/issu"

        # Results are paged based on request / response headers
        page_start = 0
        page_size = 200
        self.device_info = []
        while True:
            # Iterate until all devices are found, 100 at a time
            page_end = page_start + (page_size - 1)
            log.debug(f"Requesting devices {page_start} - {page_end}")
            self.REQUEST_HEADERS["Range"] = f"items={page_start}-{page_end}"
            response = self.session.get(url, headers=self.REQUEST_HEADERS, verify=False)

            log.debug(f"NDFC Response: {response.json()}")

            if response.status_code != 200:
                log.error("[red]Error retrieving device list:")
                log.error(f"[red]{response.text}")
                log.error("[red]Script cannot continue. Exiting...")
                sys.exit(1)

            # Store device information for later use
            for device in response.json()["lastOperDataObject"]:
                if device["serialNumber"] in self.target_devices:
                    self.device_info.append(device)

            # Increment page start for next iteration
            total_devices = int(response.headers.get("Content-Range").split("/")[1]) - 1
            log.debug(f"Total devices: {total_devices + 1}")
            if total_devices > page_end:
                log.debug("More devices to retrieve...")
                page_start += page_size
            # Break loop if we have all devices
            if total_devices <= page_end:
                log.debug("All devices found")
                break

        if len(self.device_info) == 0:
            log.error("[red]No devices found in NDFC matching provided serial numbers")
            log.error("[red]Script cannot continue. Exiting...")
            sys.exit(1)
        if not silent:
            log.info("[green]Device information retrieved successfully!")
            log.debug(f"Collected device info: {self.device_info}")

    def setImagePolicy(self):
        """
        Apply target image policy to devices
        """
        log.info(f"Setting device image policy to {config['upgrade']['policy']}...")

        # Build policy payload
        policy_body = {"mappingList": []}
        for device in self.device_info:
            policy_body["mappingList"].append(
                {
                    "policyName": config["upgrade"]["policy"],
                    "hostName": device["deviceName"],
                    "ipAddr": device["ipAddress"],
                    "platform": device["platform"],
                    "serialNumber": device["serialNumber"],
                }
            )

        url = f"{NDFC_PATH}/imagemanagement/rest/policymgnt/attach-policy"

        response = self.session.post(
            url, headers=self.REQUEST_HEADERS, json=policy_body, verify=False
        )

        log.debug(f"NDFC Response: {response.text}")

        if response.status_code != 200:
            log.error("[red]Error with setting policy on devices:")
            log.error(f"[red]{response.text}")
            log.error("[red]Script cannot continue. Exiting...")
            sys.exit(1)

    def stageAndValidate(self):
        """
        Stage image on device & run validation checks
        """
        # sereialNum is misspelled in the NDFC API
        # This may be corrected in future NDFC releases, which will break this script
        stage_body = {"sereialNum": []}
        for device in self.device_info:
            stage_body["sereialNum"].append(device["serialNumber"])

        url = f"{NDFC_PATH}/imagemanagement/rest/stagingmanagement/stage-image"
        response = self.session.post(
            url, headers=self.REQUEST_HEADERS, json=stage_body, verify=False
        )
        log.debug(f"NDFC Response: {response.text}")
        if response.status_code != 200:
            log.error("[red]Error with staging image on devices:")
            log.error(f"[red]{response.text}")
            log.error("[red]Script cannot continue. Exiting...")
            sys.exit(1)

        # Check status of image staging
        attempts = 0
        max_attempts = config["upgrade"]["timeout"] / 30
        log.info("Waiting for devices to stage image... (This may take a while)")
        log.info(
            f"Devices will be checked every 30 seconds up to max timeout of {config['upgrade']['timeout']} seconds"
        )
        while attempts < max_attempts:
            sleep(30)
            attempts += 1
            log.info(
                f"Checking device readiness status (Attempt # {attempts} of {max_attempts:.0f})"
            )
            self.checkStagingStatus()
            if self.image_staged:
                break

        # Start image validation
        stage_body = {"serialNum": [], "nonDisruptive": True}
        for device in self.device_info:
            stage_body["serialNum"].append(device["serialNumber"])
        url = f"{NDFC_PATH}/imagemanagement/rest/stagingmanagement/validate-image"
        response = self.session.post(
            url, headers=self.REQUEST_HEADERS, json=stage_body, verify=False
        )
        log.debug(f"NDFC Response: {response.text}")
        if response.status_code != 200:
            log.error("[red]Error with staging image on devices:")
            log.error(f"[red]{response.text}")
            log.error("[red]Script cannot continue. Exiting...")
            sys.exit(1)
        # Check validation status
        attempts = 0
        max_attempts = config["upgrade"]["timeout"] / 30
        log.info("Waiting for devices to validate... (This may take a while)")
        while attempts < max_attempts:
            sleep(30)
            attempts += 1
            log.info(
                f"Checking device readiness status (Attempt # {attempts} of {max_attempts:.0f})"
            )
            self.checkValidationStatus()
            if self.validated:
                break

    def checkStagingStatus(self):
        """
        Query NDFC for device status & check to see if staging
        has completed or not

        Once complete, sets self.image_staged to True
        """
        # Re-query device info to get latest status
        self.getDeviceInfo(silent=True)

        total_devices = len(self.device_info)
        ready_devices = 0
        devices_staging = 0
        error_devices = []

        # Check status of each device
        for device in self.device_info:
            if device["imageStaged"] == "Success":
                ready_devices += 1
                continue
            elif device["imageStaged"] == "In-Progress":
                devices_staging += 1
                continue
            else:
                error_devices.append(device["serialNumber"])
                self.target_devices.remove(device["serialNumber"])
                total_devices -= 1
                continue

        log.debug(f"Current device status: {self.device_info}")
        # Log if any devices experience an error
        if len(error_devices) > 0:
            log.error(
                f"[red]{len(error_devices)} devices experienced an error and will be removed from the upgrade list:"
            )
            log.error(f"[red]{error_devices}")

        # Log / check if devices ready
        if ready_devices == total_devices:
            self.image_staged = True
            log.info("[green]All devices staged for upgrade!")
            return
        else:
            log.info(f"Devices ready: {ready_devices} of {total_devices}")
            log.info(f"Devices staging image: {devices_staging}")

    def checkValidationStatus(self):
        """
        Query NDFC for device status & check to see if validation
        has completed or not

        Once complete, sets self.image_staged to True
        """
        # Re-query device info to get latest status
        self.getDeviceInfo(silent=True)

        total_devices = len(self.device_info)
        ready_devices = 0
        devices_validating = 0
        error_devices = []

        # Check status of each device
        for device in self.device_info:
            if device["validated"] == "Success":
                ready_devices += 1
                continue
            elif device["validated"] == "In-Progress":
                devices_validating += 1
                continue
            else:
                error_devices.append(device["serialNumber"])
                self.target_devices.remove(device["serialNumber"])
                total_devices -= 1
                continue

        log.debug(f"Current device status: {self.device_info}")
        # Log if any devices experience an error
        if len(error_devices) > 0:
            log.error(
                f"[red]{len(error_devices)} devices experienced an error and will be removed from the upgrade list:"
            )
            log.error(f"[red]{error_devices}")

        # Log / check if devices ready
        if ready_devices == total_devices:
            self.validated = True
            log.info("[green]All devices ready for upgrade!")
            return
        else:
            log.info(f"Devices ready: {ready_devices} of {total_devices}")
            log.info(f"Devices validating image: {devices_validating}")

    def upgradeImage(self):
        """
        Execute image upgrade on list of devices
        """
        log.info("Assembling device list for upgrade...")
        # Note: As of NDFC 12.1.3b, "package" is misspelled as "pacakge"
        # in a few of the API parameters (shown below). This payload may
        # need to be updated if a future NDFC release corrects the typo
        upgrade_body = {
            "devices": [],
            "epldOptions": {"golden": False, "moduleNumber": "ALL"},
            "epldUpgrade": False,
            "issuUpgrade": True,
            "issuUpgradeOptions1": {
                "disruptive": True,
                "forceNonDisruptive": False,
                "nonDisruptive": False,
            },
            "issuUpgradeOptions2": {"biosForce": False},
            "pacakgeInstall": False,
            "pacakgeUnInstall": False,
            "reboot": False,
            "rebootOptions": {"configReload": "false", "writeErase": "false"},
        }

        # Add devices to upgrade list
        for device in config["devices"]:
            upgrade_body["devices"].append(
                {"serialNumber": device, "policyName": config["upgrade"]["policy"]}
            )

        # Send device payload to NDFC for upgrade
        log.info("Initiating upgrade process...")
        url = f"{NDFC_PATH}/imagemanagement/rest/imageupgrade/upgrade-image"
        response = self.session.post(
            url, headers=self.REQUEST_HEADERS, json=upgrade_body, verify=False
        )

        if response.status_code != 200:
            log.error("[red]Error with starting upgrade:")
            log.error(f"[red]{response.text}")
            log.error("[red]Script cannot continue. Exiting...")
            sys.exit(1)

        log.info("[green]Device upgrade request sent to NDFC for processing!")
        log.debug(f"NDFC Response: {response.text}")

    def checkUpgradeStatus(self):
        """
        Query NDFC for current status of requested device upgrades

        One all devices are upgraded, sets self.upgrades_completed to True
        """
        # Re-query device info to get latest status
        self.getDeviceInfo(silent=True)

        total_devices = len(self.device_info)
        devices_complete = 0
        devices_upgrading = 0
        error_devices = []

        for device in self.device_info:
            if device["upgrade"] == "Success":
                devices_complete += 1
                continue
            elif device["upgrade"] == "In-Progress":
                devices_upgrading += 1
                continue
            else:
                error_devices.append(device["serialNumber"])
                self.target_devices.remove(device["serialNumber"])
                total_devices -= 1
                continue

        log.debug(f"Current device status: {self.device_info}")

        # Log if any devices hit an error
        if len(error_devices) > 0:
            log.error(f"[red]{len(error_devices)} devices hit an error during upgrade:")
            log.error(f"[red]{error_devices}")

        if devices_complete == total_devices:
            log.info("[green]All devices upgraded successfully!")
            self.upgrades_completed = True
        else:
            log.info(f"Devices complete: {devices_complete} of {total_devices}")
            log.info(f"Devices still upgrading: {devices_upgrading}")


def startUpgrade() -> None:
    """
    Handle NDFC login & kick off upgrade process
    """
    ndfc = NDFC()

    # If username / password provided, get auth token
    if AUTH_MODE == "USERPASS":
        ndfc.getAuthToken()

    # Validate NDFC Version
    ndfc.getNDFCVersion()

    # Get device IP / Serial mappings
    ndfc.getDeviceInfo()

    # If stage-image is True, apply image policy & run staging / validation
    # Otherwise we assume this is done already & skip to running the upgrade
    if config["upgrade"]["stage-image"]:
        ndfc.setImagePolicy()
        # Wait for image policy to be applied
        log.info("Waiting for image policy compliance check...")
        sleep(30)
        ndfc.stageAndValidate()
    else:
        # If stage-image is False, assume devices are already staged / validated
        ndfc.image_staged = True
        ndfc.validated = True

    # Check if we hit timeout waiting for devices to be ready
    if not ndfc.image_staged and not ndfc.validated:
        log.error("[red]Timeout waiting for devices to be ready for upgrade")
        log.error("[red]Script cannot continue. Exiting...")
        sys.exit(1)

    # Start upgrade process
    ndfc.upgradeImage()

    # Check to see if devices are ready for upgrade
    attempts = 0
    max_attempts = config["upgrade"]["timeout"] / 30
    log.info("Waiting for devices to complete upgrades... (This may take a while)")
    log.info(
        f"Devices will be checked every 30 seconds up to max timeout of {config['upgrade']['timeout']} seconds"
    )
    while attempts < max_attempts:
        sleep(30)
        attempts += 1
        log.info(
            f"Checking device upgrade status (Attempt # {attempts} of {max_attempts:.0f})"
        )
        ndfc.checkUpgradeStatus()
        if ndfc.upgrades_completed:
            break

    # Check if we hit timeout waiting for device upgrade
    if not ndfc.upgrades_completed:
        log.error("[red]Timeout waiting for devices to complete upgrade")
        log.error("[red]Script cannot continue. Exiting...")
        sys.exit(1)


def loadConfig() -> None:
    """
    Load configuration file
    """
    log.info("Loading config file...")
    global config
    with open("./config.yaml", "r") as file:
        # Config load
        config = yaml.safe_load(file)
        try:
            # Config validation
            config_schema.validate(config)
        except SchemaError as e:
            log.error("[red]Failed to validate config.yaml. Error:")
            log.error(f"[red]{e}")
            sys.exit(1)
        log.info("[green]Config loaded!")
        num_devices = len(config["devices"])
        log.info(f"Found {num_devices} devices to upgrade.")


def startScheduler() -> None:
    """
    Start background scheduler & add tasks
    """
    global config
    log.info("Starting scheduler...")

    # Init background scheduler
    bg = BackgroundScheduler()
    bg.start()

    schedule = config["schedule"]

    # Create upgrade job based on config schedule
    upgrade_job = DateTrigger(
        run_date=datetime(
            year=int(schedule["year"]),
            month=int(schedule["month"]),
            day=int(schedule["day"]),
            hour=int(schedule["hour"]),
            minute=int(schedule["minute"]),
        ),
        timezone=schedule["timezone"],
    )

    # Add upgrade job to scheduler
    bg.add_job(
        func=startUpgrade,
        trigger=upgrade_job,
        name="Run Upgrade",
        # Uncomment below to force job to run immediately if scheduled time has passed
        # misfire_grace_time=None,
    )
    log.info("[green]Scheduler started & tasks loaded!")

    # Check jobs queue
    jobs = bg.get_jobs()
    next_runs = [f"> Job: {job.name}, Next run: {job.next_run_time}" for job in jobs]
    log.info(f'Next run time: \n{f"{chr(10)}".join(next_runs)}')

    # Run / wait until jobs completed
    try:
        while True:
            sleep(5)
            # Check if any jobs remaining
            jobs = bg.get_jobs()
            if len(jobs) == 0:
                log.info("[orange]No jobs remaining, shutting down...")
                bg.shutdown(wait=False)
                log.info("[orange]Shutdown complete")
                sys.exit(0)
    except KeyboardInterrupt:
        log.warning("[orange]Received shutdown signal...")
        bg.shutdown(wait=False)
        log.warning("[orange]Shutdown complete")


if __name__ == "__main__":
    loadConfig()
    startScheduler()
