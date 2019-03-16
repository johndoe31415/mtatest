# mtatest
mtatest is a small utility that checks your own mail transfer agent (MTA) for
correct configuration. It will try to send mails under email addresses that
your account is not authorized to use (assuming you have authenticated mail
transfer enabled) and it will check your relay configuration. The sent emails
should contain information about which test was performed, respectively, and if
it's a good or bad thing that the email actually came through.

## Testcases
Here's a detailed breakdown of the testcases:

  * InsecureAuthenticationTest: Try to login to the MTA without a secure (TLS)
    connection. This must fail because otherwise the password is transmitted in
    clear text over the Internet without you realizing it.
  * WrongPasswordTest: Login with wrong password. Must fail.
  * RightPasswordTest: Login with correct password. Must succeed.
  * AuthenticatedSelfMailTest: Authenticate and send an email to self. Must
    succeed.
  * UnauthenticatedSelfMailTest: Do not authenticate and send an email address
    from own address to myself. Should fail.
  * InvalidFromAddressOwnDomain: Send from an email address that does not exist
    (aaaaaaaa@{MYDOMAIN}, where {MYDOMAIN} is replaced by your own domain).
    Should fail in case there is no catchall/wildcard match, otherwise should
    succeed.
  * InvalidFromAddressPeerDomain: Send an email address from a valid address
    that the MTA handles to yourself. This should fail because you should not
    be authorized to use that address.
  * InvalidFromAddressRelayDomain: Send am email address over your own MTA
    using a from address that your MTA does not handle at all. Must fail.
  * AuthenticatedOpenRelay: Authenticate and try to use as a relay (i.e., the
    FROM address is not handled at all my the MTA and neither is the RCPT
    address). Must fail.
  * UnauthenticatedOpenRelay: Same as AuthenticatedOpenRelay, but don't even
    bother to authenticate. Must fail.
  * AuthenticatedForgedFromHeader: Authenticate, but have a mismatched envelope
    FROM  from the actual mail "From" header. Should fail, but might be
    acceptable to pass (depending on your configuration).

## Usage
The usage is quite straightforward:

```
$ ./mtatest.py --help
usage: mtatest.py [-h] [-u user] [-P filename] [-V mail_address]
                  [-i mail_address] [-r mail_address] [-v]
                  proto:host[:port] [proto:host[:port] ...]

positional arguments:
  proto:host[:port]     Tuple of protocol, hostname and port of the mail
                        server to test. Protocol can be either smtp or smtps.
                        Port may be omitted and defaults to 25 for smtp or 465
                        for smtps.

optional arguments:
  -h, --help            show this help message and exit
  -u user, --username user
                        When testing also authenticated SMTP, this specifies
                        the username to use.
  -P filename, --passphrase-file filename
                        When testing authenticated SMTP, this file contains
                        the passphrase. If omitted, you are prompted on the
                        command line.
  -V mail_address, --valid-address mail_address
                        Gives a valid mail address that the authenticated user
                        is allowed to use.
  -i mail_address, --valid-address-noauth mail_address
                        Gives an address that is valid under control of the
                        MTA under test, but that is not usable under the given
                        account name.
  -r mail_address, --relay-address mail_address
                        Gives a valid relay address. DO NOT use a
                        gmail/hotmail address for this since they might block
                        your whole mailserver when its relaying settings are
                        misconfigured. Use a service like trash-mail.com
                        instead (i.e., that you can read but that won't
                        blacklist your domain because of spoofy looking emails
                        coming in).
  -v, --verbose         Increase verbosity. Can be specified multiple times.
```

For example, let's say you own domains mydomain.com and myotherdomain.com. Your
username is info@mydomain.com and a valid email address that this user is
allowed to use is equally info@mydomain.com. The MTA also handles mail for
myfriend.com and the info@mydomain.com user is not allowed to use any
myfriend.com email addresses. However, info@myfriend.com is your friend's valid
email address. Lastly, you have setup a trash email address trash@trashmail.com
that you have read access to. You would test yout MTA by doing:

```
$ ./mtatest.py -u info@mydomain.com -V info@mydomain.com -i info@myfriend.com -r trash@trashmail.com smtp:mydomain.com smtps:mydomain.com
Passphrase for info@mydomain.com: 
InsecureAuthenticationTest: Success {TestFinished: ConnectionPhase.Connected / SMTP AUTH extension not supported by server.}
WrongPasswordTest: Success {TestFinished: ConnectionPhase.Connected / (535, b'5.7.8 Error: authentication failed:')}
RightPasswordTest: Success {TestFinished: ConnectionPhase.LoggedIn / None}
AuthenticatedSelfMailTest: SuccessIfMailDelivered {TestFinished: ConnectionPhase.MessageAccepted / None}
UnauthenticatedSelfMailTest: SuccessIfMailNotDelivered {TestFinished: ConnectionPhase.MessageAccepted / None}
InvalidFromAddressOwnDomain: Success {TestFinished: ConnectionPhase.LoggedIn / {'info@mydomain.com': (553, b'5.7.1 <aaaaaaaaaaaa@mydomain.com>: Sender address rejected: not owned by user info@mydomain.com')}}
InvalidFromAddressPeerDomain: Success {TestFinished: ConnectionPhase.LoggedIn / {'info@mydomain.com': (553, b'5.7.1 <info@myfriend.com>: Sender address rejected: not owned by user info@mydomain.com')}}
InvalidFromAddressRelayDomain: Success {TestFinished: ConnectionPhase.LoggedIn / {'info@mydomain.com': (553, b'5.7.1 <trash@trashmail.com>: Sender address rejected: not owned by user info@mydomain.com')}}
UnauthenticatedOpenRelay: Success {TestFinished: ConnectionPhase.LoggedIn / {'trash@trashmail.com': (554, b'5.7.1 <trash@trashmail.com>: Relay access denied')}}
AuthenticatedOpenRelay: Success {TestFinished: ConnectionPhase.LoggedIn / {'trash@trashmail.com': (553, b'5.7.1 <invalid_invalid@gmail.com>: Sender address rejected: not owned by user info@mydomain.com')}}
AuthenticatedForgedFromHeader: SuccessIfMailNotDelivered {TestFinished: ConnectionPhase.MessageAccepted / None}
InsecureAuthenticationTest: Skipped {None}
WrongPasswordTest: Success {TestFinished: ConnectionPhase.Connected / (535, b'5.7.8 Error: authentication failed:')}
RightPasswordTest: Success {TestFinished: ConnectionPhase.LoggedIn / None}
AuthenticatedSelfMailTest: SuccessIfMailDelivered {TestFinished: ConnectionPhase.MessageAccepted / None}
UnauthenticatedSelfMailTest: SuccessIfMailNotDelivered {TestFinished: ConnectionPhase.MessageAccepted / None}
InvalidFromAddressOwnDomain: Success {TestFinished: ConnectionPhase.LoggedIn / {'info@mydomain.com': (553, b'5.7.1 <aaaaaaaaaaaa@mydomain.com>: Sender address rejected: not owned by user info@mydomain.com')}}
InvalidFromAddressPeerDomain: Success {TestFinished: ConnectionPhase.LoggedIn / {'info@mydomain.com': (553, b'5.7.1 <info@myfriend.com>: Sender address rejected: not owned by user info@mydomain.com')}}
InvalidFromAddressRelayDomain: Success {TestFinished: ConnectionPhase.LoggedIn / {'info@mydomain.com': (553, b'5.7.1 <trash@trashmail.com>: Sender address rejected: not owned by user info@mydomain.com')}}
UnauthenticatedOpenRelay: Success {TestFinished: ConnectionPhase.LoggedIn / {'trash@trashmail.com': (554, b'5.7.1 <trash@trashmail.com>: Relay access denied')}}
AuthenticatedOpenRelay: Success {TestFinished: ConnectionPhase.LoggedIn / {'trash@trashmail.com': (553, b'5.7.1 <invalid_invalid@gmail.com>: Sender address rejected: not owned by user info@mydomain.com')}}
AuthenticatedForgedFromHeader: SuccessIfMailNotDelivered {TestFinished: ConnectionPhase.MessageAccepted / None}
```

## License
GNU GPL-3.
