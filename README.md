# Cisco NDFC - NX-OS Upgrade Scheduler

This code repository provides an example of how schedule automatic firmware upgrades of Cisco NX-OS switches via Cisco Nexus Dashboard Fabric Controller (NDFC).

This code performs the following process:

- Takes in a config file containing a date/time for upgrade & list of device serial numbers
- Creates a scheduled job to execute device upgrades at the desired time
- (Optional) Applies NDFC Image policy to devices
    - This includes staging the image & validating compatibility
- Executes device upgrades through NDFC at scheduled date / time

## Contacts

- Matt Schmitz (<mattsc@cisco.com>)

## Solution Components

- Cisco Nexus Dashboard Fabric Controller (NDFC)
- Cisco NX-OS Switching

> Note: Requires minimum NDFC version 12.1.3b & may not be compatible with future releases

## Installation/Configuration

### **Step 1 - Clone repo:**

```bash
git clone <repo_url>
```

### **Step 2 - Install required dependencies:**

```bash
pip install -r requirements.txt
```

### **Step 3 - Provide Schedule & Device list**

The script uses a `config.yaml` file to store the desired execution schedule, device list, and upgrade parameters.

A sample config file has been provided at `example-config.yaml` (also shown below). Please copy this file & edit - then save as `config.yaml` within the script directory.

```yaml
schedule:
  year: 2024
  month: 01
  day: 01
  hour: 03
  minute: 30
  timezone: America/New_York

upgrade:
  policy: "nx-os10_4_1"
  stage-image: True
  timeout: 3600

devices:
  - AAAAAAAAAAA
  - BBBBBBBBBBB
```

For the upgrade schedule, we can provide a date & time to execute the upgrade. All date/time values must be numeric values (ex. `01` instead of `January`). Timezone must be provided in [IANA](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) timezone format (ex. `America/New_York` or `ETC/UTC`).

Under the `upgrade` config section:

- `policy` contains the name of the desired image policy to apply to the devices
- `stage-image` is `True` or `False`. If `True`, the script will ensure the correct image policy is applied to the devices, and run the staging & validation steps within NDFC prior to upgrade. If `False`, the script will only attempt to run the upgrade at the time of execution. Note that in this case, the NDFC administrator must have already manually completed the staging & validation steps within NDFC - otherwise the upgrade will fail.
- `timeout` is the maximum amount of time (in seconds) that the script will wait for staging/validation & image upgrades to complete. For example, if set to `120`, then the script would only wait two minutes for image staging & validation to run before assuming something went wrong & exiting. Please note that if the timeout value is exceeded, the script will stop execution. Since image copy, validation, and device upgrade/reboot may take a significant amount of time - this value must be large enough to allow for those items to complete. This timeout value is applied separately to image validation/staging & device upgrades - so if the timeout was `1200`, this would be twenty minutes maximum for image staging/validation & an additional twenty minutes maximum for device upgrades.

Lastly, the `devices` section contains a list of devices to upgrade by serial number.

### **Step 4 - Provide NDFC Information**

Next, we need to provide information on how to connect to NDFC & the login credentials. This information is handled through environment variables, which can be passed to the app via a local `.env` file (or the appropriate container system).

A `sample.env` file has been provided (along with the example below).

```bash
NDFC_API_KEY=<API key here>
NDFC_USER=<NDFC username>
NDFC_PASS=<NDFC password>
NDFC_DOMAIN=local
NDFC_HOST=ndfc.example.local
NDFC_DEBUG=False
```

In order to authenticate to NDFC, we must provide **either** a API key **or** a username/password combination. If API key is provided, then the code will prefer this over username/password.

`NDFC_DOMAIN` specifies which login domain to use. If you're using the local NDFC authentication store, specify `local` here.

`NFDC_HOST` is the IP address or hostname of the NDFC server.

`NDFC_DEBUG` is `False` by default. If enabled, this will output additional logging while the script runs that may be helpful in troubleshooting.

## Usage

### Running locally

Run the application with the following command:

```
python3 ndfc_upgrade_scheduler.py
```

The script will begin running & write logs to the local console.

Upon startup, the script initializes a background task scheduler & loads the configured schedule date/time into the scheduler for when to execute.

Upon hitting the scheduled date/time, the script begins the upgrade process through NDFC. If `stage-image` is `True` in the configuration file, then first we re-apply the image policy to the devices. This step allows us to automatically have NDFC run the image staging & validation processes. The script will then wait & query NDFC every 30 seconds to check the status of these tasks.

> Note: If `stage-image` is `False`, the NDFC administrator **must** apply the policy & run image staging/validation manually prior to the script running. Otherwise, when the script runs, it will only issue the command to NDFC to begin the upgrades - which NDFC will reject since the devices are not ready.

Once image staging & validation has been completed (if this step was enabled), the script will attempt to kick off the image upgrades. Once started, the script will query NDFC every 30 seconds to monitor the progress.

### Docker

A docker image has been published for this container at `ghcr.io/gve-sw/gve_devnet_ndfc_upgrade_scheduler`

This image can be used by creating the config & .env files as specified above - then providing them to the container image:

```
docker run --env-file <path-to-env-file> -v <path-to-config.yaml>:/app/config.yaml -d ghcr.io/gve-sw/gve_devnet_ndfc_upgrade_scheduler:latest
```

Alternatively, a `docker-compose.yml` file has been included as well to quickly deploy this application.

Once the container has started, the script follows the same execution path as described in the [Running Locally](#running-locally) section above.

# Screenshots

### Sample script output

```text
> python3 ndfc_upgrade_scheduler.py 

[12:38:30] INFO     Found username and password, using username and password for authentication
           INFO     Loading config file...
           INFO     Config loaded!
           INFO     Found 2 devices to upgrade.        
           INFO     Starting scheduler...
           INFO     Scheduler started
           INFO     Added job "Run Upgrade" to job store "default"
           INFO     Scheduler started & tasks loaded!  
           INFO     Next run time:
                    > Job: Run Upgrade, Next run: 2024-01-10 12:39:00-05:00
     
[12:39:00] INFO     Running job "Run Upgrade (trigger: date[2024-01-10 12:39:00 EST])          
           INFO     Successfully authenticated to NDFC 
           INFO     Querying NDFC for device information...
     
[12:39:01] INFO     Device information retrieved successfully!
           INFO     Setting device image policy to 10_4_2...
     
[12:39:02] INFO     Waiting for devices to be ready for upgrade... (This may take a while)
           INFO     Devices will be checked every 30 seconds up to max timeout of 3000 seconds
     
[12:39:32] INFO     Checking device readiness status (Attempt # 1 of 100)
[12:39:34] INFO     Devices ready: 0 of 2
           INFO     Devices staging image: 2           
           INFO     Devices validating image: 0        
     
[12:40:04] INFO     Checking device readiness status (Attempt # 2 of 100)
[12:40:05] INFO     Devices ready: 0 of 2
           INFO     Devices staging image: 1        
           INFO     Devices validating image: 1        
     
[12:40:35] INFO     Checking device readiness status (Attempt # 3 of 100)
[12:40:36] INFO     Devices ready: 0 of 2
           INFO     Devices staging image: 0           
           INFO     Devices validating image: 2        
     
[12:41:06] INFO     Checking device readiness status (Attempt # 4 of 100)
[12:41:08] INFO     Devices ready: 2 of 2
           INFO     Devices staging image: 0           
           INFO     Devices validating image: 0        
     
[12:44:47] INFO     All devices ready for upgrade!     
           INFO     Assembling device list for upgrade...
           INFO     Initiating upgrade process...      
           INFO     Device upgrade request sent to NDFC for processing!
           INFO     Waiting for devices to complete upgrades... (This may take a while)
           INFO     Devices will be checked every 30 seconds up to max timeout of 3000 seconds
     
[12:45:17] INFO     Checking device upgrade status (Attempt # 1 of 100)
[12:45:19] INFO     Devices complete: 0 of 2           
           INFO     Devices still upgrading: 2         
     
[12:45:49] INFO     Checking device upgrade status (Attempt # 2 of 100)
[12:45:50] INFO     Devices complete: 0 of 2           
           INFO     Devices still upgrading: 2         
     
[12:46:20] INFO     Checking device upgrade status (Attempt # 3 of 100)
[12:46:21] INFO     Devices complete: 1 of 2           
           INFO     Devices still upgrading: 2         
     
[12:46:51] INFO     Checking device upgrade status (Attempt # 4 of 100)
[12:46:53] INFO     Devices complete: 2 of 2           
           INFO     Devices still upgrading: 2           
           INFO     Job "Run Upgrade (trigger: date[2024-01-10 12:39:00 EST])" executed successfully
```

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER

<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
