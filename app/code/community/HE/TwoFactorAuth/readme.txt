# Sentry
## OpenMage Two Factor Authentication Module

### Authors
- Greg Croasdill, Human Element, Inc http://www.human-element.com
- Gregg Milligan, Human Element, Inc http://www.human-element.com
- Aric Watson, Nexcess.net     https://www.nexcess.net/
- Trevor Hartman, Hydrobuilder.com  https://hydrobuilder.com

### License  
- GPL  -- https://www.gnu.org/copyleft/gpl.html

### Purpose
Sentry Two-Factor Authentication will protect your OpenMage store and customer data by adding an extra check to authenticate
your Admin users before allowing them access. Developed as a partnership between the Human Element OpenMage Development team
and Nexcess Hosting, Sentry Two-Factor Authentication for OpenMage is easy to setup and admin users can quickly login.

### Supported Providers (more to come)
The following __Two Factor Authentication__ providers are supported at this time.

#### Duo Security
For more information on Duo security's API, please see -
- https://www.duosecurity.com

#### Google Authenticator
For more information on Google Authenticator, please see -
- https://github.com/google/google-authenticator/wiki
- https://support.google.com/accounts/answer/180744?hl=en&ref_topic=1099588

### Referanced work

Some code based on previous work by Jonathan Day jonathan@aligent.com.au
- https://github.com/magento-hackathon/Magento-Two-factor-Authentication

Some code based on previous work by Michael Kliewe/PHPGangsta
- https://github.com/PHPGangsta/GoogleAuthenticator
- http://www.phpgangsta.de/

----
### Notes -
1. Installing this module will update the AdminUser table in the OpenMage database to add a twofactor_google_secret and twofactor_disable
fields for storing the local GA key and for disabling two factor on a per user basis respectively. It is safe to remove these fields
once the module is removed.

2. If you get locked out of admin because of a settings issue, loss of your provider account or other software related issue, you can *temporarily disable* the second factor authentication - 
 - Place a file named __tfaoff.flag__ in the root directory of your OpenMage installation.
 - Login to OpenMage's Admin area without the second factor.  
 - Update settings or disable Sentry
 - Remove the tfaoff.flag file to re-enable two factor authentication.
