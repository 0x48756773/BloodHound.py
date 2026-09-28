# BloodHound.py
![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/bloodhound.svg)
![License: MIT](https://img.shields.io/pypi/l/bloodhound.svg)

BloodHound.py is a Python based ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/).

This version of BloodHound.py is **only compatible with BloodHound 4.2 or newer**. For the 3.x range, use version 1.1.1 via pypi. As of version 1.3, BloodHound.py only supports Python 3, Python 2 is no longer tested and may break in the future.

## Limitations
BloodHound.py currently has the following limitations:
- Supports most, but not all BloodHound (SharpHound) features. See [Additional collection methods](#additional-collection-methods) for what the newer methods do and do not cover.
- Kerberos authentication support is in beta. If you get errors, try using `--auth-method ntlm`. If that fixes the problem, please open an issue.

## Installation and usage
You can install the ingestor via pip with `pip install bloodhound`, or by cloning this repository and running `python setup.py install`, or with `pip install .`.
BloodHound.py requires `impacket`, `ldap3` and `dnspython` to function.

The installation will add a command line tool `bloodhound-python` to your PATH.

To use the ingestor, at a minimum you will need credentials of the domain you're logging in to.
You will need to specify the `-u` option with a username of this domain (or `username@domain` for a user in a trusted domain). If you have your DNS set up properly and the AD domain is in your DNS search list, then BloodHound.py will automatically detect the domain for you. If not, you have to specify it manually with the `-d` option.

By default BloodHound.py will query LDAP and the individual computers of the domain to enumerate users, computers, groups, trusts, sessions and local admins. 
If you want to restrict collection, specify the `--collectionmethod` parameter, which supports the following options (similar to SharpHound):
- *Default* - Performs group membership collection, domain trust collection, local admin collection, and session collection
- *Group* - Performs group membership collection
- *LocalAdmin* - Performs local admin collection
- *RDP* - Performs Remote Desktop Users collection
- *DCOM* - Performs Distributed COM Users collection
- *Container* - Performs container collection (GPO/Organizational Units/Default containers)
- *PSRemote* - Performs Remote Management (PS Remoting) Users collection
- *DCOnly* - Runs all collection methods that can be queried from the DC only, no connection to member hosts/servers needed. This is equal to Group,Acl,Trusts,ObjectProps,Container
- *Session* - Performs session collection
- *Acl* - Performs ACL collection
- *Trusts* - Performs domain trust enumeration
- *LoggedOn* - Performs privileged Session enumeration (requires local admin on the target)
- *ObjectProps* - Performs Object Properties collection for properties such as LastLogon or PwdLastSet
- *CertServices* - Performs AD CS collection (certificate templates, enterprise CAs, root CAs, AIA CAs and the NTAuth store)
- *CARegistry* - Reads the CA configuration from the registry of each Certificate Authority host
- *DCRegistry* - Reads the certificate mapping configuration from the registry of each Domain Controller
- *NTLMRegistry* - Reads the NTLM restriction settings (and, on DCs, the LDAP signing and channel binding settings) from the registry
- *SMBInfo* - Collects SMB signing, dialect and OS version information from each host
- *WebClientService* - Checks whether the WebClient (WebDAV) service is running on each host
- *LdapServices* - Checks LDAP and LDAPS availability and whether signing or channel binding is required
- *GPOLocalGroup* - Reads local group membership delivered by Group Policy from SYSVOL
- *All* - Runs all methods above, except LoggedOn
- *Experimental* - Connects to individual hosts to enumerate services and scheduled tasks that may have stored credentials

Multiple collectionmethods should be separated by a comma, for example: `-c Group,LocalAdmin`

### Additional collection methods

These are the SharpHound methods that this fork adds on top of the original BloodHound.py feature set. They produce the data that BloodHound's certificate and NTLM relay attack paths are built from, so they are most useful against a BloodHound version that understands those edges.

| Method | Talks to | Needs administrative rights | Output |
| --- | --- | --- | --- |
| CertServices | LDAP (Configuration partition) | No | `certtemplates.json`, `enterprisecas.json`, `rootcas.json`, `aiacas.json`, `ntauthstores.json` |
| CARegistry | Remote registry on the CA host | Usually yes | `CARegistryData` on the enterprise CA objects |
| DCRegistry | Remote registry on each DC | Usually yes | Computer properties |
| NTLMRegistry | Remote registry on each host | Usually yes | Computer properties |
| SMBInfo | SMB session with each host | No | Computer properties |
| WebClientService | SMB named pipe on each host | No | `webclientrunning` computer property |
| LdapServices | LDAP/LDAPS on each host | No | Computer properties |
| GPOLocalGroup | SMB to SYSVOL on a DC | No | `LocalAdmins`, `RemoteDesktopUsers`, `DcomUsers` and `PSRemoteUsers` on the computer objects |

`CertServices` and `GPOLocalGroup` only need a DC, so both are included in `DCOnly`. The registry methods need the Remote Registry service, which is demand-started on current Windows versions; a first connection attempt that fails is retried once to give the service time to start.

Selecting `CARegistry` enables `CertServices` automatically, since the registry data is written out as part of the enterprise CA objects.

Things these methods deliberately do not do:

- **GPOLocalGroup** reads Restricted Groups (`GptTmpl.inf`) and Group Policy Preferences (`Groups.xml`), and honours disabled GPO links. It does not model blocked inheritance, WMI filters, security filtering on the GPO, or links on sites, so a computer may be credited with membership that filtering would have withheld. Entries that *remove* a member are ignored, since the resulting membership cannot be known from the policy file alone.
- **LdapServices** infers the signing and channel binding requirements from how the server answers a bind that carries neither. That needs a password or NT hash — a Kerberos-only run cannot probe it — and a server configured to require channel binding only "when supported" reads as not enforcing it. Where `NTLMRegistry` can read the registry of a DC, its values are used in preference.
- **CARegistry** collects the CA security descriptor and the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag in full. Enrollment agent restrictions are reported as the agent and the raw template/target GUIDs from the descriptor; they are not resolved to template names.
- **CertServices** reports each CA certificate's own thumbprint as its chain. Linking a certificate to its issuers is left to BloodHound, which has all the CA objects once they are ingested.

You can override some of the automatic detection options, such as the hostname of the primary Domain Controller if you want to use a different Domain Controller with `-dc`, or specify your own Global Catalog with `-gc`.

## Docker usage
1. Build container  
```docker build -t bloodhound .```  
2. Run container  
```docker run -v ${PWD}:/bloodhound-data -it bloodhound```  
After that you can run `bloodhound-python` inside the container, all data will be stored in the path from where you start the container.

