# Security architecture
A compiled list of information of security principles and solutions

## Cyber security

Security, risk and threat models
* CIA
* STRIDE
* DREAD
* PASTA
* Trike
* VAST

### Information security

#### Confidentiality
Guarding against improper information modification or destruction, and includes ensuring information nonrepudiation, accuracy, and authenticity.

Safeguards: Access control & protection, encryption, monitoring and training etc.

#### Integrity
Preserving authorized restrictions on access and disclosure, including a means for protecting personal privacy and proprietary information.

Safeguards: Encryption, signature, process control suchs as code testing, monitoring control sucn as message and data integrity and log analysis. Behavioral controls such a separation fo duties, rotation of duties and training etc.

#### Availability 
Ensuring timely and reliable access to, and use of, information (failure to operate due to failure, loss, error, prevention or overload).  

Safeguards: access controls, monitoring, data and computational redundancy, resilient systems, virtualization, server clustering, environmental controls, continuity of operations planning, and incident response preparedness etc.

### Privacy
* Traceability - Ability to trace the object (information) from origin to destination
* Linkability - Abilltiy to link to objects (information) going either from/to the same origin/destination.  
* Identifyability - Ability to identify the origin of an object (information),. 

## Threat sources
Information security is about blocking or reducing damage to confidentiality, integrity, and availability of information and systems.

Damaged cause from one or more of the threat sources:
* Hostile cyber or physical attacks
* Human error
* Structural failures of organization-controlled resources (e.g., hardware, software, environmental controls)  
* Natural and man-made disasters, accidents, and failures beyond the control of the

## Secrets
Types of Secrets
* Password (all forms plain, hash etc)
* Token (API-key, Session ID/key)
* Keys (private cipher keys and derivation material)
* Hashing pepper
* Checksum and hashes (potentially a secret)
* Secret data

Principles
* High entropy - Prefer long and random over strict limitations
* Keep secrets safe and seperate from other code or data
* Have a short lifecycle
* Don't rely on one kind of secrets for all your security

## Trust
In the end security relies on trust. A solution will most likely have several different
trust anchors such as:
* Identity provider
* CA in a PKI based solution.
* Peer in web of trust.
* Identity card issuer
* Co-worker at work
* Etc

Principles
* There should be a determined set of trust anchors 
* There should be a lowest level of acceptable trust
* There should be a chain of trust from a trust anchor
* Chain of trust should verifiable
* Broken chains or chains that don't meet criteria should not be trusted

### Segregation of duties
The concept of having more than one person required to complete a task.
In business the separation by sharing of more than one individual in one single task is an internal control intended to prevent fraud and error.

### Separation of concerns
Encapsulation can limit the blast radius and provide a more manage parts. 
Separation of concerns can among others be applied to areas (domains), tasks, systems, components and phases.

Principles:
* Apply separation between developmment, test and production systems.
* Apply separation between areas and teams.
* Don't share components between zones.
* Don't share components between teams.
* Have clear boundaries and controls between sepearated parts.

# MMI - Machine to machine interaction
Integration between different machines over a communication medium.

Principles:
* No trust - Don't trust the channel. Don't trust the transmitter. Don't trust the reciver.
* Follow the rules of privacy and make sure that communication is traceable, linkable and identifiable.

## DNS
DNS is crucial/weak/important

The DNS is responsible for the mapping between domain names and IP adresses.
The domain name is the public identity of the server. 

Design
* Use DNSsec for authenticating DNS records 
* Consider HA over failover
* Have zoning and multiple topologies

## TLS
TLS is a protocol for channel security. 
Correctly configured enables verification of the server via the domain name.

Trust anchors
* DNS 
* CA (certificate authority).

Weakness
* Options, variants, versions and configurations.

Best practice
* Always use TLS (almost always anyway).
* Use secure protocols and ciphers.
* Use a public trusted CA.
* Secure the DNS (with DNSsec etc).
* Use forward secrecy.
* Use full certificate chains.
* Strong private key.
* Secure private key.
* Disable insecure renegotiation.

Links
* https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

## API - REST, SOAP, GRPC etc.
Principles:
* Log calls and standardise logging.
* Use a positive security model and deny by default.
* Don't trust user input, have whitelists and disable insecure serializers.
* Use API gateways to minimize attack surface and consolidate logging and traffic inspections.
* Use TLS and consider mTLS for sensitive information.
### Authentication
* Check all possible ways to authenticate to all APIs.
* Use standard authentication, token generation, password storage,
Multi-factor.
* Use short-lived access tokens.
* Authenticate your apps (so you know who is talking to you).
* Use stricter rate-limiting for authentication, implement lockout
policies and weak password checks.

### Authorization
* Implement authorization checks with user policies and hierarchy • Don’t rely on IDs sent from client. Use IDs stored in the session
object instead.
* Check authorization each time there is a client request to
access database.
* Use random non-guessable IDs (UUIDs).

### Logging 
* Log failed attempts, denied access, input validation failures, any failures in security policy. 
* Ensure that logs are formatted to be consumable by other tools.
* Protect logs as highly sensitive.
* Include enough detail to identify attackers.
* Avoid having sensitive data in logs - If you need the information for 
debugging purposes, redact it partially.
* Integrate with SIEMs and other dashboards, monitoring, alerting
tools.

### Data exposure
* Never rely on client to filter data.
* Review all responses and adapt responses to what the API
consumers really need.
* Define schemas of all the API responses.
* Don’t forget about error responses.
* Identify all the sensitive or PII info and justify its use.
* Enforce response checks to prevent accidental data and exception
leaks.
    
## File transfer (FTP etc)
* Use sFTP with certificates.
* Encrypt and sign sensitive files, exchange keys out of band.
* Have strict access permissions.
* Use disk encryption.
* Logg activities.

## Email
* Avoid emails especially for sensitive information.
* Educate users to create awareness of phishing and other types of treats.
* Apply MFA to prevent account takeover.
* Use an email gateway that has Security capabilities usch as spam filtering, malware scanning and monitoring. 
* Use DMARC to prevent domain fraud.
* Use TLS (StarTLS) and DNS-based Authentication of Named Entities (DANE) for transport security.
* Apply secure data transfer with trusted parties e.g setting up S/MIME.

Links
* https://explained-from-first-principles.com/email/

# HMI - Human to machine interaction
Human interaction with IT software and hardware. The user interface can either be graphical, mechanical, sensors etc.

Principles 
* Do not rely on human memory.
* Be adaptable to individual need/preferences.
* Don't exclude people with special needs.
* Use standards usch as WCAG for usability.
* Don’t rely on technical knowledge on the user’s.
* Don't trust user input.
* Minimize cognitive load (visibility, constraints and affordance).
* Hide and disable functions that user isn't allowed to use.
* Mask sensitive data.
* Use 4eyes principer to avoid human errors.
* Add verification steps avoid human errors.

# HHI - Human to human interaction

Security in the interaction between humans using voice, mail etc.
Principles
* Verify that the information is safe to share.
* Verify the recipient, eg. is there trust.
* Mind the surroundings, is the location safe?
* Share information on a needs to know basis.
* All communication should be equal.
* All communication should tell the same thing.
* Trust chain should be short, preferably first hand.
* Use more trust anchors to verify information.
* Information should be complete, with provided context, to avoid misconceptions.
* Non-public written information should be enveloped, or equally protected, in transport.
* Non-public written information should be locked in when not in use.

# Machine security
 
## Application security principles
Principles
* Apply defense in depth.
* Use a positive security model (fail-safe defaults, minimize attack surface).
* Fail securely.
* Run with least privilege.
* Avoid security by obscurity (open design).
* Keep security simple (verifiable, economy of mechanism).
* Detect intrusions (compromise recording).
* Don’t trust infrastructure.
* Don’t trust services.
* Establish secure defaults (psychological acceptability).
* Keep information on a neeed to know basis.
* Clear secrets and prevent them from being shared or visible.
* State should be immutable.
* State changes should be declarative.
* Virtual machines should be avoided.
* Runtime should protect against overflows.
* Keep runtime up to date.
* Avoid unnecessary logging. 
* Mask or obfuscate sensitive information in logs.
* Don't log secrets.
* Have health checks and metrics.
* Perform peer reviews.

## Infrastructure security principles
* Have an up to date inventory list of assets.
* Have a strategy and organisation that can apply latest updates regularly and on demand.
* Have centralised logging and SIEM.
* Have a backup and recovery plan in place, make sure it is used and regularly tested.
* Apply infrastructure as code and perform peer reviews.
* Automate infrastructure and use IAAS when possible.
* Prefer an immutable infrastructure approach over mutable, eg. patching, to avoid configuration drift and snowflake servers  
* Use network zoning.
* Centralize identity and access management (IAM).
* Separate internal and external users.

## Clients
### Native clients
### Browser


# Links
[DevSecOps](http://devsecops.github.io/)
