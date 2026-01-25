# SCYTHE: `The Yara Signature Crafter` that fingerprints honeypot traffic

```                                                                               
                                         =.                      =-            
                                         .+:.==:            :=-:==             
                                          :%#=               .*%#..:.          
                                      =#%%==#*:             .+#+.+%%%#:        
                                    -%%%%%. .#%-           .*%=  -%%%%%=       
                                   *%%%%#%:   +%+         :##:    :+%%%%*.     
 @@@@@@    @@@@@@@  @@@ @@@      .#%%%=.:*.    =%*.      =%*.       .=%%%#.    @@@@@@@  @@@  @@@  @@@@@@@@  
@@@@@@@   @@@@@@@@  @@@ @@@      *%%=.   -      :%#:    *%+           .+%%*    @@@@@@@  @@@  @@@  @@@@@@@@  
!@@       !@@       @@! !@@     =%#.             .#%- .*%-              .#%=     @@!    @@!  @@@  @@!       
!@!       !@!       !@! @!!     %#.                *%*%#.                .#%.    !@!    !@!  @!@  !@!       
!!@@!!    !@!        !@!@!     -%:                  #%#.                  :%-    @!!    @!@!@!@!  @!!!:!    
 !!@!!!   !!!         @!!!     +#                 .*%#%*.                  %+    !!!    !!!@!!!!  !!!!!:    
     !:!  :!!         !!:      -%.               .#%+ .#%:                 %=    !!:    !!:  !!!  !!:       
    !:!   :!:         :!:      .%.              -%%-    +%=               .%.    :!:    :!:  !:!  :!:       
:::: ::    ::: :::     ::       ==             =%#:      -%*              =#.     ::    ::   :::   :: ::::  
:: : :     :: :: :     :         +.           *%*.        :##:           .*:      :      :   : :  : :: ::     
                                 .-         .#%=           .*%-          :.    
                                           :%#:              =%+               
                                          :*+.                ##+              
                                         :#:                  =.+*.            
                                         .                    +  .:            
                                                              =.               
                                                                               
```

## TOC 

- [SCYTHE: `The Yara Signature Crafter`](#scythe-the-yara-signature-crafter-that-fingerprints-honeypot-traffic)
  * [TOC](#toc)
  * [Description](#description)
    + [Mechanism](#mechanism)
  * [Webserver Setup](#webserver-setup)
  * [Splunk Installation](#splunk-installation)
  * [Splunk Configuration](#splunk-configuration)
  * [Flow](#flow)
  * [Aftermath of Alert Triggers](#aftermath-of-alert-triggers)
  * [Fingerprint Details](#fingerprint-details)
    + [Extended Fingerprint Collection](#extended-fingerprint-collection)
  * [Splunk Dashboard](#splunk-dashboard)
  * [UI Console](#ui-console)
  * [Use Cases](#use-cases)
    + [Scenario 1: Login Abuses](#scenario-1-login-abuses-such-as-brute-forcing-incl-password-spraying-credentials-dumping-via-ip-rotate)
    + [Scenario 2: Honeypot Credentials](#scenario-2-honeypot-credentials-for-attribution-of-threat-actors-triggering-the-tripwires)
    + [Scenario 3: Honeypot Website](#scenario-3-honeypot-website-for-threat-intelligence)
  * [Adding additional Honeypot Credentials](#adding-additional-honeypot-credentials)
    + [Manual Method](#manual-method)
    + [Automatic Method (with pastebin api POST)](#automatic-method-with-pastebin-api-post)
  * [Integration](#integration)
  * [Why create signatures from browser fingerprints](#why-create-signatures-from-browser-fingerprints)
    + [Reduce False Positives](#reduce-false-positives)
    + [Simplicity](#simplicity)
    + [High Redundancy](#high-redundancy)
  * [Moving Forward](#moving-forward)
  * [Credits - Fingerprint Collection](#credits---fingerprint-collection)


---

## Description
A fingerprinting engine that creates value from abusive traffic by generating attacker YARA signatures of various strictness levels to apply differing levels of mitigating friction. The tool further deploys honeypot entities to proactively perform threat actor attribution to identify and action against malicious actors rotating IP addresses.

### Mechanism
A honeypot webpage fingerprints a malicious actor's device and browser information. Upon visit of web page as first user session, `fingerprint.php` will be executed by a web file. The captured fingerprint gets logged and YARA signatures are created upon receiving an alert from the SIEM. 
To lure attackers, credentials can be released via `scythe` on public sites whereupon successful logon using those credentials would reveal malicious actors and fingerprinting is completed. Using SIEM to create custom rules rules such as rate-limiting thresholds or brute-forcing allows the creation of highly confident **3 YARA signatures, varying strictness**:

| Levels            | 1                                                                                                                            | 2                                                                 | 3                                                                                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Filename          | level1.yara                                                                                                               | level2.yara                                                    | level3.yara                                                                                                                                               |
| Strictness        | least                                                                                                                        | mid                                                               | high                                                                                                                                                     |
| Description       | signature bears least amount of specificity                                                                                  | signature bears broad definitions that are likely to be malicious | signature bears precise details |
| Suggested Control | apply rate-limiting policies based on this signature, ie. block the 20th requests coming in within 10 minutes for 15 minutes | throw Google re-captcha on new visits that matches this signature | block requests                                                                                                        |
<br />

## Webserver Setup
Install the package
```shell
git clone https://github.com/DJShankyShoe/scythe
```
Add your [Captcha keys](https://www.google.com/recaptcha/about/) in `scythe/php/manage.php`

![image](https://user-images.githubusercontent.com/62169971/167285295-b84e6d38-3074-4f7c-add9-6465b161fd3d.png)


Install the package & and run `install`
> Take note - if you have apache installed and have files in `/var/www/html`, you will have to tranfer them somewhere safe since this directory will be overwritten
```shell
sudo chmod +x install
sudo ./install
```

## Splunk Installation
<details>
<summary>Click for details</summary>
  
You may download a free trial here:
https://www.splunk.com/en_us/download/splunk-enterprise.html


Download .tgz format

![image](https://user-images.githubusercontent.com/83162708/149708677-d4c5ccd7-a07f-48b3-9c59-b3349786e70f.png)


Extract the splunk tar package at `/opt` </br>
```shell
sudo tar -xvzf splunk-8.2.4-87e2dda940d1-Linux-x86_64.tgz -C /opt
```

A set of admin credentials need to be created </br>
```shell
sudo /opt/splunk/bin/splunk start --accept-license
```

![image](https://user-images.githubusercontent.com/83162708/149709048-d36afa98-97da-4b3c-9e3e-589db68b28c3.png) </br>
</details>

## Splunk Configuration
<details>
<summary>Click for details</summary>

  Shift file [yaraGen.py](https://github.com/DJShankyShoe/scythe/blob/master/scripts/yaraGen.py) located at `/opt/scripts` to `/opt/splunk/bin/scripts`
  
  
### Data Input:
Click Settings > Data inputs

![image](https://user-images.githubusercontent.com/83162708/149710610-9ecfce6c-6a0a-4404-a2e7-bfa42dab5f86.png) </br>


`Add new` to Files & Directories

![image](https://user-images.githubusercontent.com/83162708/149709105-2cdb5ac9-0af9-40b5-b8fc-be2c3548e8e6.png) </br>


File or Directories: `/var/log/scythe/status.txt`

![image](https://user-images.githubusercontent.com/62169971/167299167-b7095849-00fa-4a1f-8386-a229ad46fa9c.png) </br>


## Field Extraction:
source = `/var/log/scythe/status.txt` <br>
Under Results: `Event Actions` > `Extract Fields`

![image](https://user-images.githubusercontent.com/62169971/167299778-0dd4ad20-a912-40c7-bf0b-e5fa2a5452a3.png)


Select `Regular Expression` and hit next

![image](https://user-images.githubusercontent.com/62169971/167299889-1be3d07e-6b05-47e8-955b-610837af494b.png)


Start highlighting the required fields and give them appropriate names (userID, email, status)

![image](https://user-images.githubusercontent.com/62169971/167300129-50fb9687-8e04-4508-9ee0-d7e5d12323d0.png)


Validate them and save extraction

![image](https://user-images.githubusercontent.com/62169971/167300220-0bb9e06c-797a-441b-a655-3c593b8098f1.png)


### Splunk Alert:
Examples: <br>
- Block Alert: `source="/var/log/scythe/status.txt" status="successful" | table userID` <br>
- Captcha Alert: `source="/var/log/scythe/status.txt" status="failed" | stats count by userID | dedup userID | where count > 3` <br>

![image](https://user-images.githubusercontent.com/62169971/167300394-05948cfe-7798-424a-b287-c3a10985637f.png)


Click Save as alert: </br>
> Tile: block </br>
> Alert type: Real-time </br>
> Expires: 100 days </br>
> When triggered: Run a script, File name: `yaraGen.py`

![image](https://user-images.githubusercontent.com/62169971/167300653-51289915-7f54-4f42-962e-f96b1f828d3d.png)


Modify `yaraGen.py` line 98 - 103 according to the splunk alert name

![image](https://user-images.githubusercontent.com/62169971/167300734-49130936-3a04-453b-bfa0-89c1166d210a.png)

</details>

## Flow
![image](https://user-images.githubusercontent.com/62169971/167294561-673e564b-acde-4363-a5fa-658713347011.png)

1. Upon visiting the site as first user session, it will load process.php
2. Process.php responsible for creating a unique ID and loading fingerprint.php
3. Fingerprint.php collects fingerprint from the actor's device and browser
4. Fingerprint.php creates a randomly generated PHP file name for retrieving POST data
5. Fingerprint Data is POSTED to the generated PHP file
6. The generated PHP file, logs the fingerprint with unique ID in fingerprint.txt located at `/var/log/scythe`
7. The generated PHP file deletes itself after PHP is fully executed
8. Process.php will redirect the actor back to login.php and upon login, it executes check.py
9. Check.py retrieves the fingerprint for that actor by tracking the unique ID
10. Check.py uses the extracted fingerprint and attempts to find a match in a live.yara file - containing lists of attacker's signatures
11. The result of the match (if any) is processed and returned back to the site whether to perform any action `block`, `captcha`, `limit`
12. Login status is monitored by SIEM splunk and executes yaraGen.py if there is any alert
13. YaraGen.py retrieves information regarding the alert and extracts the appropriate fingerprint that is tracked by unique ID
14. YaraGen.py generates 3 main levels of Yara signatures - **Level 1**, **Level 2**, **Level 3** 
15. The approrpiate level signature is pushed to live.yara that is used for action monitoring


## Aftermath of Alert Triggers
The `yaraGen.py` located at `/opt/scripts/` will be executed </br>
It will hash the fingerprint collected and verifies for any duplicates stored in `myhash.txt`

**If Duplicate Exist:**
- Do nothing

<br>**If NO Duplicates Exist:**
- Appends new hash into myhash.txt
- Creates 3 different yara signatures and appends them into their respective file at  `/opt/signatures/`:
  1. level1.yara
  2. level2.yara
  3. level3yara
- Pushes the appropriate yara signature (based from the alert from SIEM) to yara.live (acts like rules table)


## Fingerprint Details


| **General**               | **Hardware**    | **Network**                              | **Browser**         | **Unqiue Visitor ID**   |
|     :---                  |    :---         |                :---                      |         :---        |        :---             |
| Screen Resolution         | CPU Cores       | API Status                               | Browser Permissions | FingerprintJS           |
| Browser Type              | GPU             | Country                                  | Language            |                         |
| Browser Version           |                 | Region                                   | Plugins             |                         |
| Mobile `(True/False)`     |                 | Region Name                              | Fonts               |                         |
| OS Type                   |                 | City                                     | Timezone            |                         |
| OS Version                |                 | Zip                                      | Canvas Hash         |                         |
| Cookies `(True/False)`    |                 | Latitude                                 |                     |                         |
| Flash Version             |                 | Longitude                                |                     |                         |
| AGent                     |                 | ISP                                      |                     |                         |
|                           |                 | ORG                                      |                     |                         |
|                           |                 | As                                       |                     |                         |
|                           |                 | Asname                                   |                     |                         |
|                           |                 | Reverse DNS                              |                     |                         |
|                           |                 | Mobile - Cellular Data `(True/False)`    |                     |                         |
|                           |                 | Proxy  `(True/False)`                    |                     |                         |
|                           |                 | Hosting `(True/False)`                   |                     |                         |
|                           |                 | IP Address                               |                     |                         |

### Extended Fingerprint Collection
<details>
<summary>Browser Permissions</summary>
  
`Geolocation` `Notification` `Push` `Midi` `Camera` `Microphone` `Speaker` `Device-info` `Background-fetch` `Background-sync` `Bluetooth` `Persistent-storage` `Ambient-light-sensor` `Accelerometer` `Gyroscope` `Magnetometer` `Clipboard` `Screen-wake-lock` `NFC` `Display-capture` `Accessibility-events` `Clipboard-read` `Clipboard-write` `Payment-handle` `Idle-detection` `Periodic-background-sync` `System-wake-lock` `Storage-access` `Window-placement` `Font-access` `Tabs` `Bookmarks` `UnlimitedStorage` 

</details>

<details>
<summary>Language</summary>

`Browser Language` `System Language` `User Language`
  
</details>

## Splunk Dashboard
This is sample dashboard that users can use:

![image](https://user-images.githubusercontent.com/83162708/150303178-5ed2278b-c9ee-4683-bf45-b5143927219d.png)

**Funtions of this dashboard**
- Every hash is represented by a dynamically generated unique avatar <img src="https://user-images.githubusercontent.com/83162708/150305684-edb2db2b-85b6-4c8a-a253-efba65209836.gif" width="25">
- The user can select the hash to check the 3 Yara signatures
- The user can input IP to check for associated hashes
- Check IP locations

Click [HERE](https://github.com/DJShankyShoe/scythe/blob/master/splunk/dashboard.xml) to get dashboard source code




## UI Console
A basic [UI](https://github.com/DJShankyShoe/scythe/blob/master/scripts/ui.py) located at `/opt/scripts/` is created to get live status of user logins and alerts. 

![image](https://user-images.githubusercontent.com/62169971/167307643-50d6a78f-5e52-4274-bc6b-ea57e610fc46.png)

It can be used to view current user `fingerprints` and `signatures` (if alerts are created)

![image](https://user-images.githubusercontent.com/62169971/167307673-462f4168-97f6-4ced-84c3-0c1913cdb14c.png)
![image](https://user-images.githubusercontent.com/62169971/167307697-5aad1616-b784-422f-bb05-e8634df48d0d.png)




## Use Cases

Attackers have been using multiple methods to exploit sites, services, steal credentials and more. When successful, attackers can use that to gain access to restricted sites, information or  permissions. We provide proactive approaches to engage the attackers early on.

<br /><br />

### Scenario 1: Login Abuses such as Brute-forcing (incl. Password Spraying, Credentials Dumping) via IP Rotate
> Attackers may bypass rate-limiting controls by employing IP-rotate techniques, thus we fingerprint the attackers device and browser for attribution

`Attackers may attempt to perform bruteforce`

![image](https://user-images.githubusercontent.com/62169971/150117223-8ada9e1c-25ba-4154-8849-51174fc80229.png)
---
`A rule written to detect bruteforce attempts will be triggered and executes yaraGen.py to create signatures`

![image](https://user-images.githubusercontent.com/62169971/150117272-71b0b165-ace3-44f0-9760-1c5799904d11.png)
---
`For this scenario, a match between the fingerprint and yara level-2 rule resulted in presenting recaptcha to prevent/slow down bruteforce attempts by attackers`<br />
**The image below presents a non-exhausive illustration of an attacker being challenged with recaptcha**

![image](https://user-images.githubusercontent.com/62169971/150121180-0525666e-2928-49fc-aa56-6f1646edcdaa.png)

<br /><br /><br />

### Scenario 2: Honeypot Credentials for Attribution of Threat Actors Triggering the Tripwires
> Releasing fake credentials on such places will lure attackers to our site, giving us information about their fingerprints.

`Release of our honeypot website credentials on pastebins`

![image](https://user-images.githubusercontent.com/62169971/150104029-e7cfb3ad-775f-4a50-9ad3-4c2ea24f1e40.png)
---
`When attacker's crawler picks it up, the attacker would attempt to log in using our credentials on our honeypot site`

![image](https://user-images.githubusercontent.com/62169971/150104616-2ac73027-093a-4c6b-8464-efa16cf1a070.png)
---
`Upon logon, rule written to detect login will be triggered and executes yaraGen.py to create signatures`

![image](https://user-images.githubusercontent.com/62169971/150110059-de2ba7b0-1a66-48a3-ace3-40fa6260b7ec.png)
---
`For this scenarios, a match between the fingerprint and yara level-3 rule resulted in a block on the attacker usage to organisation network` <br>
**Do note that, from the picture below, the attacker is blocked from accessing the honeypot site which is only an example. Organisation can use those signatures on their actual network to deal with attackers**

![image](https://user-images.githubusercontent.com/62169971/167305017-fc3d5702-ea67-4f2e-87c7-c4dc0d2afd3a.png)

<br /><br /><br />

### Scenario 3: Honeypot Website for Threat Intelligence
> Launching scythe with a honeypot / fake site (of a similar industry) to fingerprint malicious traffic for signature creation. The honeypot could be placed under a dummy subdomain of an organization. This feed of signatures can then be shared with the open-source threat intelligence community or consumed internally.

`The attacker used the unkowing Paypal honeypot released credentials to sign into a honeypot account`

![image](https://user-images.githubusercontent.com/62169971/150458414-941acfdf-3a40-4414-91f2-be31bf8c3574.png)
---
`Upon successful sign in using the released credentials, an alert is generated that executes yaraGen.py to create signatures`

![image](https://user-images.githubusercontent.com/62169971/150458537-13a9056d-b1ae-41a8-bc10-3236046690b8.png)
---
`The user gets blocked from accessing the organisation's domain network using the yara level-3 generated signature`

![image](https://user-images.githubusercontent.com/62169971/167305017-fc3d5702-ea67-4f2e-87c7-c4dc0d2afd3a.png)

<br /><br /><br />


## Adding additional Honeypot Credentials
### Manual Method

When logging in, `login/index.php` will compare the entered credentials to a `creds.txt` lookup file. If any of those credentials exist and match in the lookup file, the actor will be successfully logged in.

The 1st field represents `email address` while the 2nd field represents `password`. The 3rd field does not represent anythin but you would have to place something to prevent PHP errors.

![image](https://user-images.githubusercontent.com/62169971/150639460-5fd6f6ba-641c-420b-8541-db90d7347a23.png)
---

To add credentials, append new credentials to the next line using the mentioned format

![image](https://user-images.githubusercontent.com/62169971/150639765-59b2ab78-6cf2-4ee7-9ba4-c13595e65ca1.png)

<br />

### Automatic Method (with pastebin api POST)
This method automatically creates the credentials and appends them to `creds.txt`. Additional step is carried out where the created credentials are released on Pastebin to lure attackers. This is achieved by executing [pastebin_api.py](https://github.com/DJShankyShoe/scythe/blob/master/scripts/pastebin_api.py) located at `/opt/scripts/`

```shell
sudo python3 pastebin_api.py
```
Upon executing, it asks for `custom/default` message

|                | Custom Option   | Default Options           |
|  :---          |      :---:      |      :---:                |
| Email Field    | `Custom`        | `Automatically Generated` |
| Password Field | `Custom`        | `Automatically Generated` |
| Message Field  | `Custom`        | `Default`                 |
| Append Creds into `creds.txt`  | `Automatic`   | `Automatic` |

Before executing `pastebin_api.py`, you will have to assign your `dev_api_key` in that file. `dev_api_key` can be retrieved from `https://pastebin.com/doc_api` (you will need an Pastebin account)

![image](https://user-images.githubusercontent.com/62169971/150641133-a88e9853-0d40-4234-88c8-548df66a25d6.png)

After successfuly executing `pastebin_api.py`, the honeypot credentials would be uploaded to Pastbin and appended to `creds.txt`

![image](https://user-images.githubusercontent.com/62169971/150641245-a423db0f-0080-4089-9ab4-0c7ae184e5cd.png)

![image](https://user-images.githubusercontent.com/62169971/150641491-ca3fb1ec-763b-49db-8198-d3b75662be4c.png)

![image](https://user-images.githubusercontent.com/62169971/150641295-fc3abc2e-3a61-40b6-98bf-e39e74a935a7.png)

<br /><br /><br />


## Integration

When you want the user fingerprints to be collected & logged, include the following code `require "../fingerprint.php";` in your web files. This can be placed and executed on the login page when the user has performed a **successful**/**failed** login. <br>
If you want the fingerprint extraction to be done before visiting a page, it's best to call another web file that executes the `fingerprint.php` before redirecting the user to the visited page.

The fingerprint will be logged at `/var/log/scythe/fingerprint.txt` path. So create directory if doesn't exist. **Do make sure that the log path is writable by web-service**

`yaraGen.py` is responsible for extracting fingerprint logs and converting them into signatures. Signatures can be found on the following path `/opt/signatures`. **Do make sure to create an empty file `myhash.txt` before executing `yaraGen.py`**


## Why create signatures from browser fingerprints

### Reduce False Positives
Organisations have been mostly using only IP Addresses to deal with bad actors. Sometimes this information is not enough as these IP's could come from organisations, merchants, or any shared groups. These can largely affect customers when using single information like IP for blocks, challenges or rate-limiting. Thus, to limit false positives, we can use browser fingerprints to uniquely identify bad actors among actors for defensive measures without affecting customers and merchants.

### Simplicity
It is very easy to obtain browser fingerprints using JavaScript or logs. It can be done in the background without affecting the customer’s experience. This makes it simple for organisations to deploy tools for browser fingerprinting.

### High Redundancy
Browser fingerprints can be broken down to other multiple information such as header, IP, hardware, canvas hash, etc. So even if 1 or more information is missing, a proper signature can still be crafted for various use cases and confidence levels.

## Moving Forward
- Integration of more SIEM tools
- Fingerprint more information
- Customize your own signatures easily

## Credits - Fingerprint Collection

> Network:        http://ip-api.com <br>
> Canvas:         https://codepen.io/jon/pen/rwBbgQ <br>
> Font:           https://codepen.io/run-time/pen/XJNXWV <br>
> Language:       https://codepen.io/run-time/pen/XJNXWV <br>
> Timezone:       https://codepen.io/run-time/pen/XJNXWV <br>
> Fingerprintjs:  https://github.com/fingerprintjs/fingerprintjs <br>
> Permissions:    https://stackoverflow.com/questions/62706697/how-to-enumerate-supported-permission-names-in-navigator-permissions <br>


