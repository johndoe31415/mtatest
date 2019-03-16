#!/usr/bin/python3
#	mtatest - Tool to test own MTAs for correct configuration (open relays, authentication, etc.)
#	Copyright (C) 2018-2019 Johannes Bauer
#
#	This file is part of mtatest.
#
#	mtatest is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	mtatest is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with mtatest; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import sys
import smtplib
import collections
import getpass
import argparse
import logging
import enum
import socket
import email.utils
from email.mime.text import MIMEText
from FriendlyArgumentParser import FriendlyArgumentParser

ServerAddress = collections.namedtuple("ServerAddress", [ "proto", "host", "port" ])

class TestFinishedException(Exception):
	def __init__(self, phase, thrown):
		Exception.__init__(self)
		self._phase = phase
		self._thrown = thrown

	@property
	def phase(self):
		return self._phase

	@property
	def thrown(self):
		return self._thrown

	def __str__(self):
		return "TestFinished: %s / %s" % (self.phase, str(self.thrown))

class ExpectedResult(enum.IntEnum):
	PreAuthRejection = 0			# Rejection of "login" phase
	SuccessfulLogin = 1				# Login successful
	EarlyRejection = 2				# Refusal to accept message
	DeferredRejection = 3			# Acceptance of message, but non-delivery
	Delivery = 4					# Delivery of email

class Prerequisite(enum.IntEnum):
	UsedProtocolSMTP = 0
	AuthenticationAvailable = 1
	ValidEmailAddressAvailable = 2
	ValidNoAuthorizedAddressAvailable = 3
	RelayEmailAddressAvailable = 4

class ConnectionPhase(enum.IntEnum):
	PreConnect = 0
	Connected = 1
	LoggedIn = 2
	MessageAccepted = 3

class TestResult(enum.IntEnum):
	Skipped = 0
	Failed = 1
	SuccessIfMailDelivered = 2
	SuccessIfMailNotDelivered = 3
	Success = 4

class MailTesterTestcase(object):
	def __init__(self, server_address, valid_address, valid_address_noauth, valid_relay_address, valid_username, valid_passphrase):
		self._server_address = server_address
		self._valid_address = valid_address
		self._valid_address_noauth = valid_address_noauth
		self._valid_relay_address = valid_relay_address
		self._valid_username = valid_username
		self._valid_passphrase = valid_passphrase
		self._starttls = False
		self._auth_username = None
		self._auth_passphrase = None
		self._from_addr = None
		self._to_addr = None
		self._from_header_override = None
		self._text = "This is a raw template."
		self._expect = [ ExpectedResult.Delivery ]
		self._prerequisites = [ ]
		self.setup()

	def _craft_email(self):
		body = self._text
		body += "\n\n"
		if ExpectedResult.Delivery in self._expect:
			body += "This message should be delivered successfully."
		else:
			body += "This message SHOULD NOT be delivered."
		body += "\n\n"
		body += "Server: %s port %d using %s\n" % (self._server_address.host, self._server_address.port, self._server_address.proto)
		if self._server_address.proto == "smtp":
			body += "STARTTLS used: %s\n" % (self._starttls)
		if self._auth_username is not None:
			body += "Authenticated as: %s\n" % (self._auth_username)
		else:
			body += "No authentication provided.\n"
		body += "MAIL FROM: %s\n" % (self._from_addr)
		body += "RCPT TO: %s\n" % (self._to_addr)
		if self._from_header_override:
			body += "'From' header field: %s\n" % (self._from_header_override)
		mail = MIMEText(body)

		test_class_name = self.__class__.__name__
		if ExpectedResult.Delivery in self._expect:
			mail["Subject"] = "Testmail PASS: %s" % (test_class_name)
		else:
			mail["Subject"] = "Testmail FAIL: %s" % (test_class_name)
		mail["From"] = self._from_header_override or self._from_addr
		mail["To"] = self._to_addr
		mail["Date"] = email.utils.formatdate()
		return mail

	def prerequisite_fulfilled(self, prerequisite):
		if prerequisite == Prerequisite.UsedProtocolSMTP:
			return self._server_address.proto == "smtp"
		elif prerequisite == Prerequisite.AuthenticationAvailable:
			return (self._valid_username is not None)
		elif prerequisite == Prerequisite.ValidEmailAddressAvailable:
			return (self._valid_address is not None)
		elif prerequisite == Prerequisite.ValidNoAuthorizedAddressAvailable:
			return (self._valid_address_noauth is not None)
		elif prerequisite == Prerequisite.RelayEmailAddressAvailable:
			return (self._valid_relay_address is not None)
		else:
			raise NotImplementedError(prerequisite)

	def _run(self):
		conn = None
		phase = ConnectionPhase.PreConnect
		try:
			if self._server_address.proto == "smtp":
				conn = smtplib.SMTP(host = self._server_address.host)
			else:
				conn = smtplib.SMTP_SSL(host = self._server_address.host)
			if (self._server_address.proto == "smtp") and self._starttls:
				conn.starttls()

			phase = ConnectionPhase.Connected

			if self._auth_username is not None:
				conn.login(self._auth_username, self._auth_passphrase)
			phase = ConnectionPhase.LoggedIn

			if self._from_addr is not None:
				# Try to send email
				mail = self._craft_email()
				conn.sendmail(self._from_addr, self._to_addr, mail.as_string())
				phase = ConnectionPhase.MessageAccepted
		except Exception as e:
			raise TestFinishedException(phase, e)
		finally:
			if conn:
				conn.quit()

		raise TestFinishedException(phase, None)

	def run(self):
		try:
			self._run()
		except TestFinishedException as e:
			test_result = e
		return (self.evaluate_result(test_result), test_result)

	def	check_prerequisites(self):
		return all(self.prerequisite_fulfilled(prerequisite) for prerequisite in self._prerequisites)

	def expectation_fulfilled(self, expectation, result):
		if expectation == ExpectedResult.PreAuthRejection:
			if (result.phase == ConnectionPhase.Connected) and (result.thrown is not None):
				return TestResult.Success
			else:
				return TestResult.Failed
		elif expectation == ExpectedResult.SuccessfulLogin:
			if (result.phase == ConnectionPhase.LoggedIn) and (result.thrown is None):
				return TestResult.Success
			else:
				return TestResult.Failed
		elif expectation == ExpectedResult.Delivery:
			if (result.phase == ConnectionPhase.MessageAccepted) and (result.thrown is None):
				return TestResult.SuccessIfMailDelivered
			else:
				return TestResult.Failed
		elif expectation == ExpectedResult.DeferredRejection:
			if (result.phase == ConnectionPhase.MessageAccepted) and (result.thrown is None):
				return TestResult.SuccessIfMailNotDelivered
			else:
				return TestResult.Failed
		elif expectation == ExpectedResult.EarlyRejection:
			if (result.phase < ConnectionPhase.MessageAccepted) and (result.thrown is not None):
				return TestResult.Success
			else:
				return TestResult.Failed
		else:
			raise NotImplementedError(expectation)

	def evaluate_result(self, result):
		return max(self.expectation_fulfilled(expectation, result) for expectation in self._expect)

	def setup(self):
		raise NotImplementedError()

class GenericTest():
	def __init__(self, **kwargs):
		self._args = kwargs

	def	check_prerequisites(self):
		return True

	def run(self):
		raise NotImplementedError()

class MTAHelloTest(GenericTest):
	def run(self):
		address = self._args["server_address"]
		if address.proto == "smtp":
			conn = None
			try:
				conn = socket.create_connection((address.host, address.port))
				data = conn.recv(1024)
				data = data.decode("utf-8").rstrip("\r\n")
				split_data = data.split()
				if not data.startswith("220 "):
					return (TestResult.Failed, "Expected 220 greeting, received: %s" % (data))
				if len(split_data) < 4:
					return (TestResult.Failed, "Expected at least four tokens in 220 greeting, received: %s" % (data))
				if split_data[1] != address.host:
					return (TestResult.Failed, "Hostname mismatch in 220 greeting, we connected to %s but server advertieses %s" % (address.host, split_data[1]))
				if split_data[2] != "ESMTP":
					return (TestResult.Failed, "MTA does not advertise ESMTP.")
				return (TestResult.Success, "220 greeting advertising ESMTP and hostname matches up with server indication.")
			except socket.gaierror as e:
				return (TestResult.Failed, "Error connecting to %s:%d: %s" % (address.host, address.port, str(e)))

			finally:
				if conn is not None:
					conn.close()
			return (TestResult.Success, "OK")
		else:
			return (TestResult.Failed, "Protocol not implemented: %s" % (address.proto))

class InsecureAuthenticationTest(MailTesterTestcase):
	def setup(self):
		self._prerequisites += [ Prerequisite.UsedProtocolSMTP, Prerequisite.AuthenticationAvailable ]
		self._expect = [ ExpectedResult.PreAuthRejection ]
		self._text = "This test tries to send authentication information over an insecure (smtp) channel without any TLS. The mail server must reject the login for this test to pass."
		self._auth_username = self._valid_username
		self._auth_passphrase = "aaaaaaaaaaaaaa"

class WrongPasswordTest(MailTesterTestcase):
	def setup(self):
		self._starttls = True
		self._prerequisites += [ Prerequisite.AuthenticationAvailable ]
		self._expect = [ ExpectedResult.PreAuthRejection ]
		self._text = "Supply wrong password should fail."
		self._auth_username = self._valid_username
		self._auth_passphrase = "aaaaaaaaaaaaaa"

class RightPasswordTest(WrongPasswordTest):
	def setup(self):
		super().setup()
		self._expect = [ ExpectedResult.SuccessfulLogin ]
		self._text = "Supply correct password should pass."
		self._auth_passphrase = self._valid_passphrase

class AuthenticatedSelfMailTest(MailTesterTestcase):
	def setup(self):
		self._prerequisites += [ Prerequisite.AuthenticationAvailable, Prerequisite.ValidEmailAddressAvailable ]
		self._expect = [ ExpectedResult.Delivery ]
		self._text = "Try to send an email to myself."
		self._starttls = True
		self._auth_username = self._valid_username
		self._auth_passphrase = self._valid_passphrase
		self._from_addr = self._valid_address
		self._to_addr = self._valid_address

class UnauthenticatedSelfMailTest(AuthenticatedSelfMailTest):
	def setup(self):
		super().setup()
		self._auth_username = None
		self._expect = [ ExpectedResult.EarlyRejection, ExpectedResult.DeferredRejection ]
		self._text = "Try to send an email to myself without any authentication."

class InvalidFromAddressOwnDomain(AuthenticatedSelfMailTest):
	def setup(self):
		super().setup()
		self._prerequisites += [ Prerequisite.ValidEmailAddressAvailable ]
		self._expect = [ ExpectedResult.EarlyRejection, ExpectedResult.DeferredRejection ]
		self._text = "Sending an email from an address that we don't own, but that's our own domain."
		if self._valid_address is not None:
			self._from_addr = "aaaaaaaaaaaa@" + self._valid_address.split("@")[1]

class InvalidFromAddressPeerDomain(AuthenticatedSelfMailTest):
	def setup(self):
		super().setup()
		self._prerequisites += [ Prerequisite.ValidNoAuthorizedAddressAvailable ]
		self._expect = [ ExpectedResult.EarlyRejection, ExpectedResult.DeferredRejection ]
		self._text = "Sending an email from an address that the MTA handles, but that our user does not have any access to."
		self._from_addr = self._valid_address_noauth

class InvalidFromAddressRelayDomain(AuthenticatedSelfMailTest):
	def setup(self):
		super().setup()
		self._prerequisites += [ Prerequisite.RelayEmailAddressAvailable ]
		self._expect = [ ExpectedResult.EarlyRejection, ExpectedResult.DeferredRejection ]
		self._text = "Sending an email from an address that we don't own, not even our own domain."
		self._from_addr = self._valid_relay_address

class AuthenticatedOpenRelay(AuthenticatedSelfMailTest):
	def setup(self):
		super().setup()
		self._prerequisites += [ Prerequisite.RelayEmailAddressAvailable ]
		self._expect = [ ExpectedResult.EarlyRejection, ExpectedResult.DeferredRejection ]
		self._text = "Mail server configured as an open relay when authentication is used."
		self._from_addr = "invalid_invalid@gmail.com"
		self._to_addr = self._valid_relay_address

class UnauthenticatedOpenRelay(AuthenticatedOpenRelay):
	def setup(self):
		super().setup()
		self._text = "Mail server configured as an open relay when no authentication is used."
		self._auth_username = None

class AuthenticatedForgedFromHeader(AuthenticatedSelfMailTest):
	def setup(self):
		super().setup()
		self._prerequisites += [ Prerequisite.RelayEmailAddressAvailable ]
		self._expect = [ ExpectedResult.EarlyRejection, ExpectedResult.DeferredRejection ]
		self._text = "From header mismatches the actual sender."
		self._from_header_override = "invalid_invalid@gmail.com"
		self._to_addr = self._valid_relay_address

class MailTester(object):
	_ConnParameters = collections.namedtuple("ConnParameters", [ "username", "passphrase", "starttls" ])
	_log = logging.getLogger("smtptest")
	_TestSuite = [ MTAHelloTest, InsecureAuthenticationTest, WrongPasswordTest, RightPasswordTest, AuthenticatedSelfMailTest, UnauthenticatedSelfMailTest, InvalidFromAddressOwnDomain, InvalidFromAddressPeerDomain, InvalidFromAddressRelayDomain, UnauthenticatedOpenRelay, AuthenticatedOpenRelay, AuthenticatedForgedFromHeader ]

	def __init__(self, args):
		self._args = args
		if self._args.username is not None:
			if self._args.passphrase_file is None:
				self._passphrase = getpass.getpass("Passphrase for %s: " % (self._args.username))
			else:
				with open(self._args.passphrase_file) as f:
					self._passphrase = f.readline().rstrip("\r\n")
		else:
			self._passphrase = None

	def run(self):
		# Create a test plan first
		testcases = [ ]
		for server_address in self._args.target:
			for testclass in self._TestSuite:
				testcase = testclass(server_address = server_address, valid_address = self._args.valid_address, valid_address_noauth = self._args.valid_address_noauth, valid_relay_address = self._args.relay_address, valid_username = self._args.username, valid_passphrase = self._passphrase)
				testcases.append(testcase)

		for testcase in testcases:
			name = testcase.__class__.__name__
			if testcase.check_prerequisites():
				(result, details) = testcase.run()
			else:
				(result, details) = (TestResult.Skipped, None)
			print("%s: %s {%s}" % (name, result.name, details))

def proto_host_port(text):
	tokens = text.split(":")
	if len(tokens) not in [ 2, 3 ]:
		raise argparse.ArgumentTypeError("expected 2 or 3 arguments, but got %d" % (len(tokens)))
	if tokens[0] not in [ "smtp", "smtps" ]:
		raise argparse.ArgumentTypeError("protocol must be either smtp or smtps, you specified %s" % (tokens[0]))
	if len(tokens) == 2:
		tokens.append({
			"smtp":		"25",
			"smtps":	"465",
		}[tokens[0]])
	tokens[2] = int(tokens[2])
	return ServerAddress(*tokens)

parser = FriendlyArgumentParser()
parser.add_argument("-u", "--username", metavar = "user", help = "When testing also authenticated SMTP, this specifies the username to use.")
parser.add_argument("-P", "--passphrase-file", metavar = "filename", help = "When testing authenticated SMTP, this file contains the passphrase. If omitted, you are prompted on the command line.")
parser.add_argument("-V", "--valid-address", metavar = "mail_address", help = "Gives a valid mail address that the authenticated user is allowed to use.")
parser.add_argument("-i", "--valid-address-noauth", metavar = "mail_address", help = "Gives an address that is valid under control of the MTA under test, but that is not usable under the given account name.")
parser.add_argument("-r", "--relay-address", metavar = "mail_address", help = "Gives a valid relay address. DO NOT use a gmail/hotmail address for this since they might block your whole mailserver when its relaying settings are misconfigured. Use a service like trash-mail.com instead (i.e., that you can read but that won't blacklist your domain because of spoofy looking emails coming in).")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity. Can be specified multiple times.")
parser.add_argument("target", metavar = "proto:host[:port]", nargs = "+", type = proto_host_port, help = "Tuple of protocol, hostname and port of the mail server to test. Protocol can be either smtp or smtps. Port may be omitted and defaults to 25 for smtp or 465 for smtps.")
args = parser.parse_args(sys.argv[1:])

tester = MailTester(args)
tester.run()
