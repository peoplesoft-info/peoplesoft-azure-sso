# Azure/SAML SSO in PeopleSoft

I had the requirement to implement Microsoft's Azure single sign on (SSO) in
PeopleSoft without purchasing Oracle's or Appsian's solution. I found
[Simon O'Donoghue's blog post](https://simonodonoghue.blog/2019/11/30/integrating-adfs-into-campus-solutions-9-2/),
but it was incomplete as it only covered identity provider (Azure) initiated
sign on. In this repository, I have code examples and describe how to do Azure
SSO using SAML which includes both service provider (PeopleSoft) initiated SSO
and identity provider (Azure) initiated SSO. Theoretically this can be extended
for any SAML capable identity provider such as ADFS, CAS, or Shibboleth;
however, parts of this document will be Azure specific.

I had looked into OAuth 2 support, however, it looks like Oracle did not
include support for OAuth 2 for signing into PeopleSoft from supported
platforms such as Azure, therefore SAML had to be the route I chose since I
found the most documentation relating to SAML sign on support in PeopleSoft.

I wrote this assuming the reader has very little knowledge as many people have
different backgrounds and knowledge of the various working systems. Perhaps
some items will come across as obvious within this document, but others
may find it very useful. I lacked knowledge that others took for granted when
I was working on this, and it can be very difficult to fill in the gaps. I hope
this will allow any PeopleSoft developer with at least some knowledge in
PeopleSoft programming to be able to implement SAML authentication. A systems
administrator will need to be involved in the identity provider setup and some
PeopleSoft infrastructure setup that is required.

## Overview

To make this work, I used PeopleSoft's custom sign on PeopleCode feature to
read the SAML response from the identity provider (IdP). The
[SetAuthenticationResult](https://docs.oracle.com/cd/F52213_01/pt859pbr3/eng/pt/tpcl/PeopleCodeBuilt-inFunctionsAndLanguageConstructs_S.html#u6bffa7ed-ded8-4200-8597-d335e185083c)
PeopleCode method is used to assign the correct PeopleSoft Operator ID (OPRID)
based on data from the SAML response. Some Java code is used to validate the
SAML signature.

For Service Provider/SP-initiated SAML authentication, I modified the sign on
HTML to redirect to the identity provider through the provided authentication
request (`AuthnRequest`), saving the current URL in the IdP redirect as the
Relay State so PeopleSoft knows where to redirect back upon authentication to
support deep linking.

## Platform

This code used Simon's code as a starting point and was upgraded for new
versions. The Java uses a non-vulnerable log4j version as well as OpenSAML 4.
I developed and tested the code on the Windows platform on PeopleTools 8.59.
I additionally added code to generate a SAML authentication request for SP
initiated SSO support.

These steps have been confirmed to work for PeopleTools 8.58 so long as you
use the `java-8.58` folder. Everything else will work as mentioned.

The PeopleTools 8.59 Java code will work just fine with PeopleTools 8.60.

# Setup Checklist

These are the steps required to set up SAML SSO on any PeopleSoft environment:

1. Copy the project or manually create the signon peoplecode and related pages and
iScripts for SP initiated signon and user switching.
2. Modify the application package `SAML_AUTH:CustomSignonOptions` to reflect
your environment. If using the simplified code (no user switch version), customize
the `FUNCLIB_SAML` PeopleCode instead.
3. Create the `SAML_AUTH_OPRIDS` [SQL object](#a-note-on-sql-saml_auth_oprids)
4. Build all records for auditing or selecting users.
5. Register any components/pages needed for signon, e.g. user selection pages
6. [Set up Azure](#azure-setup) for the two properties: Reply Assertion URL
(fluid homepage) and the entity ID.
7. Create the [guest user](#user-profile-configuration).
8. Configure the [signon PeopleCode](#signon-peoplecode-configuration).
9. Copy an existing web profile in use by PIA or create a new one and
[configure](#web-profile-configuration).
10. Install custom signinsaml.html and signout.html pages into PIA. ([Customize
for the environment](#sign-on-html-files))
11. Configure PIA to use the new web profile.
12. [Compile and Install the SAML JAR](#saml-java-code) into the application server.
13. Install the configuration file in the directory that is embedded/hard-coded
within the JAR file, or set the `SAML_CONFIG` environment variable if using the
JAR configured for the environment variable.
14. [Update the configuration file](#java-code-configuration) to use the
information from Azure.
15. Restart APPSRV and PIA processes.
16. Clear browser cookies and cache.
17. Test and [troubleshoot](#troubleshooting).

# IdP Initiated SAML Process

## Overview

To start, I began with the identity provider initiated SAML process because
the service provider initiated just adds a redirect at the start of the
process while the rest is the same. For Azure, I was able to go to
[My Applications](https://myapplications.microsoft.com) when logged into the
tenant and click on a link to start the process. I set up a new "app" in Azure
to add the link in `My Applications`. Clicking the link initiated a POST
request to the configured PeopleSoft server with a `SAMLResponse` parameter.

## Azure setup

You must enable SSO in Azure for PeopleSoft. The
[Azure SSO](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/add-application-portal-setup-sso)
instructions contain information on how to set up SSO for gallery apps.
PeopleSoft is a non-gallery app, but the setup up will be similar. Only two
items are necessary for Azure, the Identifier/Entity ID and the Reply URL or
Assertion Consumer Service URL. You may pick anything for the entity ID, but
be sure to remember the value as PeopleSoft will need to know it.

![Azure setup screenshot](images/Azure%20setup%201.png)

The Reply URL will be the PeopleSoft target page. Do not use the login page
(i.e. any page with ?cmd=login in the URL) as this will result in an infinite
loop and PeopleSoft will not process the SAML response since it will not invoke
the sign on PeopleCode. Also, do not use the classic homepage as this seems to
cause problems. I used the fluid home page as the reply url, e.g.
`https://domain.tld/psc/<site>/<portal>/<node>/c/NUI_FRAMEWORK.PT_LANDINGPAGE.GBL`

![PeopleSoft sign-in process](images/PeopleSoft%20signon%20process.png)

Because a request is made for a component, if the user is not signed in, the
custom sign on PeopleCode should execute which should read the SAML response
and either log the user in with data from the SAML response, or reject it and
show the login page.

At this point, nothing more is needed if the PeopleCode can determine the
PeopleSoft Operator ID from only the Name ID. I had Azure configured to use
the UPN as the name ID, but I also configured Azure to send a claim for the
employee ID which my PeopleCode could use to determine the proper operator ID
to log in as.

To customize the name ID value, please
[view the Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-saml-claims-customization)
on customizing claims. To add custom claims such as the employee ID that
might be stored in Azure, please
[view the Microsoft documentation on custom claims](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims).

Be sure to save the metadata URL for use later in the [Java setup](#java-code-configuration).

## PeopleSoft Setup

### User Profile Configuration
Create a new user profile to be used as a guest user (if your environment
does not have one already). This user needs no security.

![Add a new User Profile for guest access](images/PeopleSoft%20guest%20user%20setup%201.png)

Make sure there is no ID specified for the guest user.

![ID tab of guest User Profile](images/PeopleSoft%20guest%20user%20setup%202.png)

There are no roles for this user.

![Roles tab of guest User Profile](images/PeopleSoft%20guest%20user%20setup%203.png)

You may see a warning about a symbolic ID that does not exist if you chose to
leave it blank. This is OK to ignore and is likely more secure to have no
symbolic ID on the guest user.

![Missing symbolic ID warning](images/PeopleSoft%20guest%20user%20setup%204.png)

### Web Profile Configuration

Web Profile setup can be found at the menu navigation PeopleTools >
Web Profile > Web Profile Configuration.
I copied the existing web profile over to one called `SAML` with the
menu item PeopleTools > Web Profile > Copy Web Profile. I imagine creating a
new one or editing the existing web profile in place will also work. Do note
that if you copy one, not all parameters are copied, so make sure you carefully
review the web profile setup, particularly the custom properties tab.

![Add a new Web Profile](images/PeopleSoft%20web%20profile%20setup%201.png)

In case I broke anything in the configuration, I set up a new PIA site to point
to the new web profile so I could access and login natively with the old PIA site
in case the web profile settings were incorrect.

I should note here that you cannot leave the basic authentication domain blank
during the PIA setup. You will get "knock knock" errors or unauthorized errors
(see the [troubleshooting section](#knockknockurl-is-not-authorized) for more
details). I suspect that you can leave it blank if you override the
authentication domain on the web profile configuration.

I did not change anything on the `General` tab of the web profile. In case it
matters, I have a screenshot of my environment below.

![General Web Profile Tab](images/PeopleSoft%20web%20profile%20setup%202.png)

On the `Security` tab, make sure to enable public user access and enter the
user created from the [User profile section](#user-profile-configuration).

![Security Web Profile Tab](images/PeopleSoft%20web%20profile%20setup%203.png)

My environment had nothing set up in the virtual addressing tab, your
environment may differ.

For cookie rules, I simply had the basic setup from before I did Azure SSO.

![Cookie Rules Web Profile Tab](images/PeopleSoft%20web%20profile%20setup%204.png)

Over on the authorized sites tab, you must add your identity provider as an
authorized site. For Azure, add `login.microsoftonline.com`, protocol `https`.
The CORS and Framable checkboxes must be checked. Without CORS, PeopleSoft
throws a CORS violation when the SAML is posted to PeopleSoft. Without the
Framable checkbox, the browser can throw errors about frames not allowed.

![Authorized Site Web Profile Tab](images/PeopleSoft%20web%20profile%20setup%205.png)

Change the signon/logout pages on the Look and Feel tab to new files. I named
them `signonsaml.html` and `signout.html`. Don't set the log out page to be the
login page, otherwise users cannot sign out of PeopleSoft. Set the
`Signon Page` and `Signon Error Page` to the same signin page, and set the
`Signon Result Doc Page` to the built in `signonresultdocredirect.html`
template. This is required because many pages don't work with cross-origin
browser sandboxing when the initial page has a different origin than
PeopleSoft. To work around this, the sign on PeopleCode will always issue a
redirect URL so the browser won't add extra cross-origin protections. The
result doc redirect is required to actually tell the browser to redirect to
the new URL.

The contents of the HTML files and their locations are covered in the
[next section](#sign-on-html-files).

![Look and Feel Web Profile Tab](images/PeopleSoft%20web%20profile%20setup%206.png)

Save the web profile.

[^1]: Your guest user doesn't need any roles if you can figure out how to
reliably pass data to the signon page, see the
[Possible Improvements section](#possible-improvements) for more information.

### Signon PeopleCode Configuration

Go to PeopleTools > Security > Security Objects > Signon PeopleCode. Add a new
row and type in the record where the PeopleCode exists. See
[Signon PeopleCode](#signon-peoplecode) for more information. Exec Auth Fail
should not be enabled because there is no SAML to validate if a normal
user/password authentication request fails. If you are using shared or service
accounts that multiple people use, modify the setup as mentioned in
[Service/Shared Accounts](#serviceshared-accounts).

![Signon PeopleCode Setup](images/PeopleSoft%20signon%20peoplecode%20setup.png)

## Sign on HTML Files

Two HTML files need to be created in
`$PS_CFG_HOME/webserv/<domain>/applications/peoplesoft/PORTAL.war/WEB-INF/psftdocs/<site name>`
I created [signonsaml.html](html/signonsaml.html) and
[signout.html](html/signout.html).

The signon HTML uses the error property to know where to redirect the user to.
The signon PeopleCode will issue a `SetAuthentiationResult(False)` call
with the generated authentication request. This is only needed for SP initiated
SAML single sign on processes. You can use the default login HTML form if you
only want to use Azure-initiated SAML. If the error property is not set, the
Javascript within the HTML will redirect to a page that will cause the
signon PeopleCode to fire. Do note that if you customize the HTML to go to
a page that is not the fluid home page, the URL *must* start with `/psp`
after the domain. Any `/psc` pages will not get the error text sent to the
login HTML.

In order to support deep linking, the Javascript in the HTML will store the
current URL in the `RelayState` SAML authentication request URL so it will
get passed back to PeopleSoft so the code knows where the user intended to go.
This works because the signon HTML is output for any given URL in place of the
actual component HTML, so the current URL that the user requested is still the
window's location. The code only saves the current URL as the `RelayState` if
the URL contains `/c/` (a component request), or `/s/` (an iScript request).
You may need to change the code if your environment is different. This will
prevent infinite handoff loops if the original URL was actually the signon
page.

**Make sure to modify the HTML to suit your environment**. Near the top of the
HTML in the script tag are three variables: `site`, `portal`, and `node`. These
must be updated to match your environment. They can be gleaned from the URL
when you are logged in normally as the URL normally is
`https://domain.tld/psp/<site name>/<portal name>/<node name>/<content reference>`.
I was not able to reliably determine these variables from either the URL or
from variables passed into the signon template by the PIA server. You may also
wish to change the redirect URL that the HTML goes to for retrieving the error
string/redirect URL on line 14 of [signonsaml.html](html/signonsaml.html).

## Signon PeopleCode

I created a derived/work record `FUNCLIB_SAML` and added the custom field
`SAMLAUTH` to it. In the `FieldDefault` event, [I added a function to call
the SAML validation code](peoplecode/record/FUNCLIB_SAML.SAMLAUTH.FieldDefault.txt),
which I put into an application package `SAML_AUTH:Signon`.

[Within the application package PeopleCode](peoplecode/app_package/SAML_AUTH.Signon.OnExecute%20%28no%20user%20switch%29.txt),
I invoked some Java code to validate the SAML signature, then I validate any
relevant timestamps to limit replay attacks and log the user in given data
found within the SAML response. **You must change the function
`getUserIDFromSAMLResponse()`** found at the top of the code to match your
environment. The code provided assumes the `NameID` from Azure is the UPN in
email format and that a claim was configured named `employeeid`. The code logs
in the user as the UPN minus the domain if one exists, otherwise it assumes
that OPRIDs match EMPLIDs in the system. This likely will not apply to you but
the code serves as a good example.

This code defaults to logging in `tracesql` files. You may wish to change the
logging functionality by changing the code in the `logMessage()` method. If
you keep the default, and see no log messages, make sure the `AppLogFence`
in `$PS_CFG_HOME/appserv/<name>/psappsrv.cfg` is set to 3 or 4, depending upon
the desired level. An application server restart may be required to read
changes.

## SAML Java code

I used the OpenSAML 4 java library for validating SAML signatures and
generating SAML requests. Yes, I know the names I gave it is a misnomer since
it's not specific to ADFS, but for Azure.

The [request generator class](java-pt8.59/src/main/java/saml/saml/ADFSSAMLRequestGen.java)
defaults to an unspecified NameID policy which should cause Azure to use the
default. If this does not apply to your environment, you may wish to change it
around line 130. The following are valid values:

 * UNSPECIFIED
 * EMAIL
 * X509_SUBJECT
 * WIN_DOMAIN_QUALIFIED
 * KERBEROS
 * ENTITY
 * PERSISTENT
 * TRANSIENT
 * ENCRYPTED

The [SAML signature validator class](java-pt8.59/src/main/java/saml/saml/ADFSSAMLResponseValidator.java)
reads a metadata XML file from the identity provider to validate any SAML
responses. Depending upon your identity provider, you may need to change the
code around line 149 where it loops over `getIDPSSODescriptor`. For ADFS,
apparently the function should be `getSPSSODescriptor`. If you get Java
exceptions about null pointers, try changing the function.

I could not figure out where relative paths were reading from within Java
classes, so I hardcoded an absolute path to the configuration file in each
class. I'm certain you will need to change it to suit your environment. It is
near the top of each file:

> properties.load(new FileInputStream("c:/psft/cfg/saml/saml.properties"));

### PT 8.59 code without a hard-coded path

If you want to use an environment variable to know the location of the
`saml.properties` file instead of hard-coding the path, just change the one
line:

> properties.load(new FileInputStream("c:/psft/cfg/saml/saml.properties"));

To this line:

> properties.load(new FileInputStream(System.getenv("SAML_CONFIG")));

In both of these files:
* [ADFSSAMLRequestGen.java](java-pt8.59/src/main/java/saml/saml/ADFSSAMLRequestGen.java)
* [ADFSSAMLResponseValidator.java](java-pt8.59/src/main/java/saml/saml/ADFSSAMLResponseValidator.java)

And then [compile](#compiling). Make sure to set the `SAML_CONFIG` environment
variable on your PeopleSoft Application Server to point to the location of the
`saml.properties` file.

### PT 8.58 Java code

Thanks to Brent Torgerson who modified the code for PeopleTools 8.58. The idea
is the same except the Java version it targets matches 8.58, and it uses an
environment variable to know the location of the `saml.properties` file instead
of hard-coding the path. If you use the 8.58 Java code without changing it,
make sure to set the `SAML_CONFIG` environment variable to point to the
location of the `saml.properties` file.

### Compiling

To compile, download and install [Maven](https://maven.apache.org/download.cgi),
then download and install the latest
[JDK](https://www.oracle.com/java/technologies/downloads/) on your client
workstation, not on the PeopleSoft server. Do not download the JRE as you will
get errors compiling. The file name should begin with `jdk`.

You can copy the `java-pt8.59` or `java-pt8.58` directory (depending upon the
version you are using) anywhere on your client workstation, but you must have the
`src` directory structure and the xml files in the root of the java folder. The
`bin` and `config` folders can be removed before compiling as they are not used
nor read during compile. The `java-pt8.59` or `java-pt8.58` folder (which you may
rename to anything) is where you will run the maven command below which will read
the XML files to know how to compile the code within the `src` directory.

Open a terminal such as bash or powershell and change directories to the `java`
subdirectory. Run `C:/maven/apache-maven-3.8.5/bin/mvn.cmd package` or whatever
`mvn` command is appropriate for your platform with the command line option
`package`. You should see the following output:

```
[INFO] --- maven-source-plugin:3.2.1:jar (attach-sources) @ saml ---
[INFO] Building jar: basedir\java\target\saml-1.0.0-sources.jar
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  6.082 s
[INFO] Finished at: 2022-04-12T16:06:58-00:00
[INFO] ------------------------------------------------------------------------
```

Within the `target` folder contains the file `saml-1.0.0.jar`. Copy this to any
`CLASSPATH` directory as configured in the
`$PS_CFG_HOME/appserv/<name>/psappsrv.cfg` file on your application server.
Make sure the path separators are valid for your platform, `;` for Windows, or
`:` for Linux machines otherwise you may get an error about the Java class not
being found.

I have provided a [pre-compiled source JAR for Windows](java-pt8.59/bin/saml-1.0.0.jar)
with a hard coded path of `c:/psft/cfg/saml/saml.properties` for testing
purposes. ***Do not use this JAR on production***. Please compile your own to
suit your needs. This pre-compiled JAR targets the Java version for PeopleTools
8.59.

The [pre-compiled source JAR for PeopleTools 8.58](java-pt8.58/bin/saml-1.0.0.jar)
will work as long as you set the environment variable `SAML_CONFIG` to point to
the location of your `saml.properties` file.

### Java code configuration

The Java code must be configured to match your environment. A file should be
created in the location defined in the Java code (the `saml.properties`
reference). [An example file is provided](java-pt8.59/config/saml.properties). 

The file is a simple `key=value` separated by new lines. These keys must exist:
* `federationUrl` - This will be the metadata URL that Azure will give you
after setting up the SSO "app" for PeopleSoft. The tenant ID is the GUID or
identifier after `login.microsoftonline.com`. The URL may look something like
`https://login.microsoftonline.com/<azure tenant ID>/federationmetadata/2007-06/federationmetadata.xml?appid=<PS app ID>`.
* `metadataCachePath` - This will be any folder where the application server
can write the metadata to for caching purposes to speed up validation.
* `trustEntity` - For Azure, this is simply
`https://sts.windows.net/<azure tenant ID>/` where `<azure tenant ID>` can be
gleaned from the metadata URL. This can also be found by opening up the
metadata URL in a browser and noting the `entityID` attribute in the first XML
tag (the `EntityDescriptor` XML tag). Likely this can be used for non-Azure
providers.
* `spid` - This will be the Entity ID as defined in the Azure SSO
configuration. This is a value of your choosing. I defined it as the domain.tld
for my PeopleSoft environment.
* `ssoDestination` - This is the destination URL for SP (PeopleSoft) initiated
SAML authentication requests. For Azure, this will be
`https://login.microsoftonline.com/<azure tenant ID>/saml2` where
`<azure tenant ID>` can be gleaned from the metadata URL.
* `consumerServiceURL` - This is the reply URL or Assertion Consumer Service
URL as defined in the identity provider. It really can be set to any PeopleSoft
page with the same restrictions as noted in [Azure setup](#azure-setup).

The application server will need restarted after any changes to the Java JAR
or to the `saml.properties` file.

# SP Initiated SAML Process

The key here is the `signonsaml.html` file that redirects to the identity
provider to hand off the SSO process. You may use the built-in `signon.html` if
you want to use built-in authentication for other purposes.

# Non-SSO logins

You may want to create a second PIA install pointing to a different web profile
with a different site name that contains the standard `signon.html` files for
logging in for cases where SSO is broken. Alternatively, you should still be
able to log in by invoking an HTTP POST to `/psp/<sso site>/?&cmd=login` with
the POST parameters and some cookies:

```
lcsrf_token=<matching any value contained within a lcsrftoken cookie sent along with the request>&ptmode=f&ptlangcd=ENG&ptinstalledlang=ENG&userid=<userid>&pwd=<password>&ptlangsel=ENG
```

However, doing this is outside the scope of this document.

# Service/Shared Accounts

If your environment has accounts that are shared among multiple people, an
OPRID choosing page can be constructed. The signon PeopleCode will need to be
updated to allow switching users without knowing any passwords. Because the
signon PeopleCode is called on switch user, the code can override the lack of
a password to allow the switch user to succeed anyway if the user can have
access to switch to the shared user before moving on.

First, the signon PeopleCode must be configured to run on auth fail. This is
because when the `SwitchUser` function is called, the password for the user
will not be known, so an empty string will be passed for the password. The
signon PeopleCode can then override the normal failure with a success if the
user is authorized to act as the new user.

![Signon PeopleCode Setup For User Switching](images/PeopleSoft%20signon%20peoplecode%20setup%20with%20user%20switching.png)

Be sure to restart the application server after making this change, or it will
not take effect!

A new page will need to be created to allow switching users. Then, the signon
PeopleCode will redirect to the switcher page only if it needs to be shown.
Once the user selects their desired operator ID, then final redirect to the
deep link destination can happen if the switch was successful. Don't issue
a `SwitchUser` call if they select the "default" user they are currently
logged in as since the call will fail with the error:

> SwitchUser failed.  New User Id is the same as the current User Id.

The Signon PeopleCode will need reconfigured to check for the `SwitchUser`
case. `%PSAuthResult` will be false because the password is not known and the
`%SignOnUser` will be the user they are attempting to log in as. Check
permissions against saved data (perhaps via a global variable) to see if the
current user is allowed to switch to the new user. If so, you can issue a
`SetAuthenticationResult(TRUE)` call to allow the switch user even if the
password is incorrect.

## Prebuilt project

Load the [PeopleSoft project](ps%20project/SAML_AUTH/SAML_AUTH.XML) into
Application Designer and customize or implement a new class to replace the
`SAML_AUTH:CustomSignonOptions` class to fit your environment. If you create
a new class, update `SAML_AUTH:Factory` to point to your new class. You will
also want to update `SAML_AUTH:SAMLAuthData` to match what data you will pull
from the SAML. You will have to publish the component to a menu and add
permissions to all users to the switch user component.

This project just contains some sample Signon PeopleCode and an example user
switcher page. You must still do all of the PeopleSoft configuration and setup
as noted in this document.

### A note on SQL SAML_AUTH_OPRIDS

This SQL object is not included in the project because it is unique to each
installation. The purpose of the SQL is to pull a list of OPRIDs given
information from Azure and is very specific to each install, depending on what
is stored for each user related to PeopleSoft within Azure.

For example, if you store PeopleSoft's EMPLID for each Azure user, you'd need
some SQL to pull the OPRIDs for a given EMPLID, like this:

```sql
select
    OPRID,
    EMPLID,
    ACCTLOCK,
    OPRDEFNDESC,
    1 as SORTORDER
from
    PSOPRDEFN
where
    EMPLID = :1
order by SORTORDER, OPRID, ACCTLOCK
```

Or, in the case of PeopleSoft containing OPRIDs related to an Azure UPN, you
might have something like the following SQL:

```sql
select
    opr.OPRID,
    opr.EMPLID,
    opr.ACCTLOCK,
    opr.OPRDEFNDESC,
    1 as SORTORDER
from
    PSOPRDEFN opr
    join PS_UPN_OPRID_TBL upntbl on (upntbl.OPRID = opr.OPRID)
where
    upntbl.UPN = :1
order by opr.SORTORDER, opr.OPRID, opr.ACCTLOCK
```

This would require a custom UPN_OPRID_TBL to be created that contains the link
between Azure UPN to PeopleSoft OPRID, if this is the route you choose.

Other installations may require a combination of the above, or other datapoints
from Azure claims. The SQL will need to be tailored correctly for each
installation which only you can determine will work best for your situation.

### Code customizations related to this SQL

After creating the SQL to match your situation, you will then need to modify
`SAML_AUTH:CustomSignonOptions.getAuthDataFromResponse()` to pull what you need
from Azure claims and modify
`SAML_AUTH:CustomSignonOptions.getValidOPRIDsForSAMLData()` to pass the correct
bind variables to the SQL and parse the correct columns from the SQL.
The data transfer object `SAML_AUTH:SAMLAuthData` can be modified to store the
Azure data you parse/pull out with the `getAuthDataFromResponse` method.

The sort order should be something sorted in the SQL if order matters to your
situation. The delivered code does not do anything with sort order.

# Troubleshooting

There are a lot of pieces to this integration and any number of things can go
wrong.

There are three kinds of logs that should prove helpful in troubleshooting:
1. PIA logs found in `$PS_CFG_HOME/webserv/<domain>/servers/PIA/logs` files
named `PIA_servlets0.log.0` or `PIA_servlets1.log.0`.
2. Application Server logs found in `$PS_CFG_HOME/appserv/<domain>/LOGS` files
name `APPSRV_MMDD` where MM is the two digit month and DD is the two digit day.
3. Trace SQL logs found on the application server in
`$PS_CFG_HOME/appserv/<domain>/LOGS` files with the name
`<user>_<IP>.tracesql`. Most of the time, the `<user>` will be the configured
public user as defined in the [web profile setup](#web-profile-configuration).
However, you may wish to check other recent files as I've seen logging go into
a logged-in user trace SQL file, particularly when they are initiating a new
sign in when they have already logged in.

For troubleshooting signon PeopleCode issues, Oracle recommends
```
TRACESQL=31
TRACEPC=3596
```
in the PSAPPSRV.CFG configuration file.

Always check the developer toolbar of your browser to examine the responses
from PeopleSoft. Any time you see a redirect to
`?cmd=logout&cmd=login&errorCode=<number>&languageCd=ENG`, you can look up the
error message in the file
`$PS_CFG_HOME/webserv/<domain>/applications/peoplesoft/PORTAL.war/WEB-INF/psftdocs/<site name>/errors.properties`

[This PeopleSoft document](https://docs.oracle.com/cd/F52213_01/pt859pbr3/eng/pt/tsec/UsingSignonPeopleCode-c07722.html)
may help with understanding Signon PeopleCode.

## Basic signon troubleshooting tips

When you see strange or unexpected results, these are always good first steps:

1. Clear browser cookies and cache.
2. Restart the application server and PIA.

During signon PeopleCode testing, I saw the server get into a state where
strange things don't work like branding, images, or javascript failing to
load. The above steps resolved the issue.

Also try causing an update to the Signon PeopleCode by inserting a space at the
end and saving as this sometimes causes some internal PS cache to reset.

This code defaults to logging in `tracesql` files. You may wish to change the
logging functionality by changing the code in the `logMessage()` method. If
you keep the default, and see no log messages, make sure the `AppLogFence`
in `$PS_CFG_HOME/appserv/<name>/psappsrv.cfg` is set to 3 or 4, depending upon
the desired level. An application server restart may be required to read
changes.

You may need to portal security sync after changing sites.

## Signon PeopleCode does not appear to run

If you are getting no logs, and logs are configured properly in `psappsrv.cfg`,
(see above) and the signon code is correctly configured, the problem may be
invalid syntax somewhere in the signon PeopleCode. When errors of any kind
happen during signon PeopleCode execution, the application server will silently
abort running any of the rest of the code and will assume no login happens and
will continue to use the guest user. You may wish to wrap the signon code in
a try/catch block to log any errors, otherwise there will be no information.

Also note that any changes to Signon Peoplecode configuration requires an
application server restart (it never hurts to restart web server along with the
app server).

## Bypass SP initiated SAML request

When first working on SAML SSO, start with testing identity provider (Azure)
initiated requests. Don't use the PeopleSoft signon, but instead go to Azure's
[My Applications](https://myapplications.microsoft.com/) and click on the
PeopleSoft "app" to redirect to PeopleSoft with the SAML response. Once you
have IdP initiated working, then get the SP-initiated portion working with
the provided `signonsaml.html` file.

## knockKnockURL is not authorized

If you see an error like this in the PIA_servlets log:

```
isLastSiteValid PSTrustAuthUtil.isLastSiteValid() failed for reason
'knockKnockURL is not authorized by the WebProfile's list of Authorized
Sites', sMyUrl=https://domain.tld/psp/<site>/<portal>/<node>/c/<component>,
sLastSite=https://domain.tld/psp/<site>/?cmd=checkToken, sDomain=domain.tld
PSCheckToken denied for reason 'no PS NetSession in JBridge',
PS_KKTagno=2263475, session.isNew()=false, getRemoteHost()=x.x.x.x,
getRemoteAddr()=x.x.x.x
```

The likely cause is a bad authentication domain. I once tried adding the
PeopleSoft site itself as an authorized domain but that caused more problems.
The proper solution is to set the basic authorization domain correctly during
PIA setup or set the override on the web profile.

You can check if the authentication domain is bad by adding the custom property
WebCheckToken in the custom properties of the web profile and set it to false.
Restart the web server and see if the error goes away. **This is not suitable
for production because tokens can be forged.** See
[this blog for more info](https://psadmin.io/2017/10/25/understanding-the-check-token-id-in-peopletools-8-56/).

## Error in classic homepage

Authentication issues like
```
Error in service HomepageT, CREF with URL can not be found: /psc/<site>/<portal>/<node>/?tab=DEFAULT
```
or a redirect to error code 129 or signon page with error message
```
UnAuthorized Token has been detected by the System. Please signon with your User ID and Password.
```
is because PeopleSoft does not work with posting SAML directly to the classic 
homepage. Use a different target/reply URL such as the fluid home page then
redirect to the classic home page after authentication success.

## Deep linking does not work

If you see an error page, ensure that the `Signon Error Page` field in the Web
Profile "Look and Feel" tab is set to your saml signon page and not an error
HTML page. Review [Web Profile Configuration](#web-profile-configuration) to
make sure you have completed all the steps.

## Classic homepage issues

If the classic homepage does not load properly, make sure the redirect URL
does not contain relative path items such as `..`.

## CORS or frame browser errors

Make sure the web profile is set up to allow CORS and Framable from the
origin of your identity provider.

## Error code 127

There are many possibilities that causes signon error code 127. If there are
no errors in the logs (tracesql or APPSRV), check that any relevant user
switching pages are registered as that may be the cause. A browser network
trace will likely show a signout right before the redirect to the user
switching page if the component is not registered.

## Error code 129

If you get error code 129: `UnAuthorized Token has been detected by the System.
Please signon with your User ID and Password.`, check the portal servlet logs
mentioned in [Troubleshooting](#troubleshooting).

## Branding does not show after deep linking

After signon when going directly to a non-home page URL, if the branding does
not appear and the buttons are invisible, change the code so it redirects to
`/psp/<site>/<portal>/<node>/s/WEBLIB_PTBR.ISCRIPT1.FieldFormula.IScript_StartPage?URL=`
and then the final URL. This iScript should fix the branding not coming
through. Note that this will only work for classic pages, fluid pages will not
show and it will instead dump you to the classic homepage.

The cause appears to be the macroset not properly loading on the very first
page. One way around this I found was to always redirect to a fluid page that
will redirect to your final destination by calling `ViewURL` in the component
PreBuild or PostBuild code while showing a nice redirecting message.

## Java error on line 128

During signon processing, you may see the following log line in the logs:

```
java.lang.NullPointerException at saml.saml.ADFSSAMLResponseValidator.ValidateSAMLResponse(ADFSSAMLResponseValidator.java:128)
```

The likely cause behind this is an error creating an instance of the validator
class. One possible problem could be a lack of write permissions to the
metadata cache folder set up within the `saml.properties` file. To get more
information on the problem, modify the `SAML_AUTH:Signon` PeopleCode function
`validateSAMLSignature` by adding the following code line:

> %This.common.logMessage(%ApplicationLogFence_Level1, "Instantiation log data: " | &SAMLValidator.getLogData());

after the line

> Local JavaObject &SAMLValidator = &SAMLValidatorClass.GetInstance();

so that the end function looks like this:

```
method validateSAMLSignature
   /+ &samlXML as String +/
   /+ Returns Boolean +/
   Local JavaObject &SAMLValidatorClass = GetJavaClass("saml.saml.ADFSSAMLResponseValidator");
   Local JavaObject &SAMLValidator = &SAMLValidatorClass.GetInstance();
   %This.common.logMessage(%ApplicationLogFence_Level1, "Instantiation log data: " | &SAMLValidator.getLogData());
   Local boolean &valid = &SAMLValidator.ValidateSAMLResponse(&samlXML);
   %This.common.logMessage(%ApplicationLogFence_Level1, "Validation log data: " | &SAMLValidator.getLogData());
  
   Return &valid;
end-method;
```

After another login attempt, the logs should show you the problem.

# Possible Improvements

Find a way to reliably determine the site/portal/node for generating the
IScript/signout URLs in the signon HTML template so they do not need to
be configured for each environment within the HTML file. 

OAuth 2 support appears to be built into recent versions of PeopleTools. There
may be a way of utilizing it for SSO support for any OAuth2 capable identity
provider such as Azure.

# Credits

This work would not have been possible without the following people:

* My sysadmin/DBA for all the help setting up Azure and as a sounding board
* Simon O'Donoghue for the example SAML parsing Java code found at
    * https://simonodonoghue.blog/2019/11/30/integrating-adfs-into-campus-solutions-9-2/
* Sasank Vemana for some help in understanding sign on code in blog posts and helpful comments at
    * https://pe0ples0ft.blogspot.com/2021/03/sso-deflate-base64-encode-saml.html
    * https://pe0ples0ft.blogspot.com/2015/04/conditional-redirect-in-signon.html
* Dan Iverson for how check token works:
    * https://psadmin.io/2017/10/25/understanding-the-check-token-id-in-peopletools-8-56/
* Brent Torgerson for getting the Java code to work for PeopleTools 8.58.

# Contact

If you note some improvements or missing detail, please let me know by sending
a message to peoplesoft-azure-sso at persidus dot com.
