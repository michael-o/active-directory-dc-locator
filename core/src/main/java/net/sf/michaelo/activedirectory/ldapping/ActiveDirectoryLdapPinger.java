/*
 * Copyright 2025 Michael Osipov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sf.michaelo.activedirectory.ldapping;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.CommunicationException;
import javax.naming.directory.NoSuchAttributeException;

import net.sf.michaelo.activedirectory.IntFlag;
import net.sf.michaelo.activedirectory.StringUtils;

import org.apache.tomcat.util.buf.Asn1Parser;

import static org.apache.tomcat.util.buf.Asn1Writer.writeInteger;
import static org.apache.tomcat.util.buf.Asn1Writer.writeOctetString;
import static org.apache.tomcat.util.buf.Asn1Writer.writeSequence;
import static org.apache.tomcat.util.buf.Asn1Writer.writeTag;

/**
 * A Java implementation of the <a
 * href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/895a7744-aff3-4f64-bcfa-f8c05915d2e9">LDAP
 * Ping</a> process to a domain controller. An LDAP ping probes the liveliness and capabilities of a domain controller.
 *
 * <p><b>Note</b>: This class uses JUL to print log messages, enable at least level {@code FINE} to see output.
 */
public class ActiveDirectoryLdapPinger {

	private static final byte[] ASN1_INTEGER_ZERO_BYTES = writeInteger(0);
	private static final byte[] ASN1_INTEGER_ONE_BYTES = writeInteger(1);
	private static final byte[] ASN1_ENUMERATED_ZERO_BYTES = writeTag((byte) 0x0A, new byte[] {0x00});
	private static final byte[] ASN1_BOOLEAN_FALSE_BYTES = writeTag((byte) 0x01, new byte[] {0x00});
	private static final int ASN1_ENUMERATED_TAG = 0x0A;
	private static final int ASN1_SET_TAG = 0x31;
	private static final int ASN1_CONSTRUCTED_TAG = 0x20;
	private static final int ASN1_APPLICATION_TAG = 0x40;
	private static final int ASN1_CONTEXT_SPECIFIC_TAG = 0x80;
	private static final int ASN1_LDAP_MESSAGE_SEARCH_REQUEST_TAG_NUMBER = 3;
	private static final int ASN1_LDAP_MESSAGE_SEARCH_REQUEST_AND_FILTER_TAG_NUMBER = 0;
	private static final int ASN1_LDAP_MESSAGE_SEARCH_REQUEST_EQUALITY_MATCH_FILTER_TAG_NUMBER = 3;
	private static final int ASN1_LDAP_MESSAGE_SEARCH_RESULT_ENTRY_TAG_NUMBER = 4;
	private static final int ASN1_LDAP_MESSAGE_SEARCH_RESULT_DONE_TAG_NUMBER = 5;
	private static final byte[] LDAP_MESSAGE_SEARCH_RESULT_CODE_SUCCESS_BYTES = new byte[] {0};

	private static final String NETLOGON_LDAP_ATTRIBUTE = "Netlogon";

	private static final String DEFAULT_PROTOCOL = "udp";
	private static final int DEFAULT_PORT = 389;

	private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryLdapPinger.class.getName());

	protected byte[] pingBytes(LdapPingRequest request) throws CommunicationException, NoSuchAttributeException {
		Objects.requireNonNull(request, "request cannot be null");
		String protocol = StringUtils.isNotEmpty(request.getProtocol()) ? request.getProtocol() : DEFAULT_PROTOCOL;
		if (!protocol.equalsIgnoreCase("tcp") && !protocol.equalsIgnoreCase("udp"))
			throw new IllegalArgumentException(
					String.format("Request protocol must be either 'tcp' or 'udp', but is '%s'", protocol));
		boolean preferTcp = protocol.equalsIgnoreCase("tcp");

		InetSocketAddress hostAddress = null;
		try {
			hostAddress = new InetSocketAddress(InetAddress.getByName(request.getHostName()), DEFAULT_PORT);
		} catch (UnknownHostException e) {
			CommunicationException ne = new CommunicationException("Unknown host name: " + request.getHostName());
			ne.setStackTrace(e.getStackTrace());
			throw ne;
		}

		byte[] requestBytes = asn1Encode(request);
		byte[] responseBytes = new byte[512];

		if (LOGGER.isLoggable(Level.FINE)) {
			StringBuilder message = new StringBuilder();
			message.append("Performing LDAP ping request with filter '(&");
			message.append("(NtVer=")
					.append(String.format("0x%08X", IntFlag.toFlags(request.getNtVersion())))
					.append(")");
			if (StringUtils.isNotEmpty(request.getDnsDomain()))
				message.append("(DnsDomain=").append(request.getDnsDomain()).append(")");
			if (StringUtils.isNotEmpty(request.getDnsHostName()))
				message.append("(DnsHostName=").append(request.getDnsHostName()).append(")");
			message.append(")'");
			LOGGER.fine(message.toString());
		}

		if (LOGGER.isLoggable(Level.FINE)) {
			if (preferTcp) {
				if (request.getConnectTimeout() > 0 && request.getReadTimeout() > 0)
					LOGGER.fine(String.format(
							"Creating and configuring TCP socket for %s with connect timeout %d ms and read timeout %d ms",
							hostAddress, request.getConnectTimeout(), request.getReadTimeout()));
				else if (request.getConnectTimeout() > 0)
					LOGGER.fine(String.format(
							"Creating and configuring TCP socket for %s with connect timeout %d ms",
							hostAddress, request.getConnectTimeout()));
				else if (request.getReadTimeout() > 0)
					LOGGER.fine(String.format(
							"Creating and configuring TCP socket for %s with read timeout %d ms",
							hostAddress, request.getReadTimeout()));
				else LOGGER.fine(String.format("Creating TCP socket for %s", hostAddress));
			} else {
				if (request.getReadTimeout() > 0)
					LOGGER.fine(String.format(
							"Creating and configuring UDP socket for %s with read timeout %d ms",
							hostAddress, request.getReadTimeout()));
				else LOGGER.fine(String.format("Creating UDP socket for %s", hostAddress));
			}
		}
		if (!preferTcp) {
			try (DatagramSocket sock = new DatagramSocket()) {
				if (request.getReadTimeout() > 0) sock.setSoTimeout(request.getReadTimeout());

				try {
					if (LOGGER.isLoggable(Level.FINER))
						LOGGER.finer(String.format(
								"Sending LDAP ping request (%d B): %s",
								requestBytes.length, Base64.getEncoder().encodeToString(requestBytes)));
					else LOGGER.fine(() -> String.format("Sending LDAP ping request (%d B)", requestBytes.length));
					DatagramPacket outPacket = new DatagramPacket(requestBytes, requestBytes.length, hostAddress);
					sock.send(outPacket);
				} catch (IOException e) {
					CommunicationException ne = new CommunicationException("Failed to send to " + hostAddress);
					ne.initCause(e);
					throw ne;
				}
				try {
					DatagramPacket inPacket = new DatagramPacket(responseBytes, responseBytes.length);
					sock.receive(inPacket);
					if (inPacket.getLength() > 0) {
						responseBytes = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());
						final byte[] respBytes = responseBytes;
						if (LOGGER.isLoggable(Level.FINER))
							LOGGER.finer(String.format(
									"Received LDAP ping response (%d B): %s",
									respBytes.length, Base64.getEncoder().encodeToString(respBytes)));
						else LOGGER.fine(() -> String.format("Received LDAP ping response (%d B)", respBytes.length));
					} else throw new CommunicationException("No LDAP ping response received from " + hostAddress);
				} catch (IOException e) {
					CommunicationException ne = new CommunicationException("Failed to receive from " + hostAddress);
					ne.initCause(e);
					throw ne;
				}
			} catch (SocketException e) {
				CommunicationException ne =
						new CommunicationException("Failed to create/configure UDP socket for " + hostAddress);
				ne.initCause(e);
				throw ne;
			}
		} else {
			try (Socket sock = new Socket()) {
				if (request.getReadTimeout() > 0) sock.setSoTimeout(request.getReadTimeout());
				try {
					if (request.getConnectTimeout() > 0) sock.connect(hostAddress, request.getConnectTimeout());
					else sock.connect(hostAddress);
				} catch (IOException e) {
					CommunicationException ne = new CommunicationException("Failed to connect to " + hostAddress);
					ne.initCause(e);
					throw ne;
				}

				try {
					if (LOGGER.isLoggable(Level.FINER))
						LOGGER.finer(String.format(
								"Sending LDAP ping request (%d B): %s",
								requestBytes.length, Base64.getEncoder().encodeToString(requestBytes)));
					else LOGGER.fine(() -> String.format("Sending LDAP ping request (%d B)", requestBytes.length));
					OutputStream os = sock.getOutputStream();
					os.write(requestBytes);
					os.flush();
				} catch (IOException e) {
					CommunicationException ne = new CommunicationException("Failed to send to " + hostAddress);
					ne.initCause(e);
					throw ne;
				}

				try {
					InputStream is = sock.getInputStream();
					int len = is.read(responseBytes);
					if (len > 0) {
						responseBytes = Arrays.copyOfRange(responseBytes, 0, len);
						final byte[] respBytes = responseBytes;
						if (LOGGER.isLoggable(Level.FINER))
							LOGGER.finer(String.format(
									"Received LDAP ping response (%d B): %s",
									respBytes.length, Base64.getEncoder().encodeToString(respBytes)));
						else LOGGER.fine(() -> String.format("Received LDAP ping response (%d B)", respBytes.length));
					} else if (len == 0)
						throw new CommunicationException("No LDAP ping response received from " + hostAddress);
					else throw new CommunicationException("Connection to " + hostAddress + " has been closed");
				} catch (IOException e) {
					CommunicationException ne = new CommunicationException("Failed to receive from " + hostAddress);
					ne.initCause(e);
					throw ne;
				}
			} catch (IOException e) {
				CommunicationException ne =
						new CommunicationException("Failed to create/configure TCP socket for " + hostAddress);
				ne.initCause(e);
				throw ne;
			}
		}

		byte[] netlogonBytes = asn1Decode(responseBytes);

		// Attribute 'Netlogon' was not in the LDAP response
		if (netlogonBytes == null)
			throw new NoSuchAttributeException(
					"LDAP ping response from " + hostAddress + " did not contain Netlogon attribute");

		return netlogonBytes;
	}

	/**
	 * Sends an LDAP ping request and returns a parsed response. The response needs to be cast to an actual
	 * implementation based on the {@link NetlogonNtVersion} requested. The version maps as follows:
	 *
	 * <ul>
	 *   <li>{@link NetlogonNtVersion#V5EX} to {@link NetlogonSamLogonExResponse}
	 *   <li>{@link NetlogonNtVersion#V5} to {@link NetlogonSamLogonResponse}
	 *   <li>{@link NetlogonNtVersion#V1} to {@link NetlogonSamLogonNt40Response}
	 * </ul>
	 *
	 * @param request the LDAP ping request
	 * @return Netlogon SAM Logon response, never null
	 * @throws NullPointerException if {@code request} is null
	 * @throws IllegalArgumentException if {@link LdapPingRequest#getProtocol()} is not null and neither {@code tcp} nor
	 *     {@code udp}
	 * @throws CommunicationException if any resolution, communication, decoding related problem occurs
	 * @throws NoSuchAttributeException if the LDAP ping response does not contain the {@code Netlogon} attribute
	 */
	public NetlogonSamLogonBaseResponse ping(LdapPingRequest request)
			throws CommunicationException, NoSuchAttributeException {
		byte[] netlogonBytes = pingBytes(request);

		NetlogonSamLogonBaseResponse response = null;
		if (request.getNtVersion().contains(NetlogonNtVersion.V5EX)) {
			LOGGER.fine(() -> "Converting LDAP ping response to NetlogonSamLogonExResponse");
			response = new NetlogonSamLogonExResponse(netlogonBytes);
		} else if (request.getNtVersion().contains(NetlogonNtVersion.V5)) {
			LOGGER.fine(() -> "Converting LDAP ping response to NetlogonSamLogonResponse");
			response = new NetlogonSamLogonResponse(netlogonBytes);
		} else {
			LOGGER.fine(() -> "Converting LDAP ping response to NetlogonSamLogonNt40Response");
			response = new NetlogonSamLogonNt40Response(netlogonBytes);
		}
		if (LOGGER.isLoggable(Level.FINER)) LOGGER.finer("Successfully converted LDAP ping response to " + response);
		else LOGGER.fine(() -> "Successfully converted LDAP ping response");

		return response;
	}

	private byte[] writeLdapString(String str) {
		return writeOctetString(str.getBytes(StandardCharsets.UTF_8));
	}

	private String fromLdapString(byte[] src) {
		return new String(src, StandardCharsets.UTF_8);
	}

	private byte[] asn1Encode(LdapPingRequest request) {
		byte[] ntVersionBytes = ByteBuffer.allocate(4)
				.order(ByteOrder.LITTLE_ENDIAN)
				.putInt(IntFlag.toFlags(request.getNtVersion()))
				.array();
		List<byte[]> andFilterTerms = new ArrayList<>();
		// Filter:equalityMatch
		byte[] equalityMatchFilterBytes = writeSequence(writeLdapString("NtVer"), writeOctetString(ntVersionBytes));
		equalityMatchFilterBytes[0] = (byte) (ASN1_CONTEXT_SPECIFIC_TAG
				| ASN1_CONSTRUCTED_TAG
				| ASN1_LDAP_MESSAGE_SEARCH_REQUEST_EQUALITY_MATCH_FILTER_TAG_NUMBER);
		andFilterTerms.add(equalityMatchFilterBytes);
		// Filter:equalityMatch
		if (StringUtils.isNotEmpty(request.getDnsDomain())) {
			equalityMatchFilterBytes =
					writeSequence(writeLdapString("DnsDomain"), writeLdapString(request.getDnsDomain()));
			equalityMatchFilterBytes[0] = (byte) (ASN1_CONTEXT_SPECIFIC_TAG
					| ASN1_CONSTRUCTED_TAG
					| ASN1_LDAP_MESSAGE_SEARCH_REQUEST_EQUALITY_MATCH_FILTER_TAG_NUMBER);
			andFilterTerms.add(equalityMatchFilterBytes);
		}
		// Filter:equalityMatch
		if (StringUtils.isNotEmpty(request.getDnsHostName())) {
			equalityMatchFilterBytes =
					writeSequence(writeLdapString("DnsHostName"), writeLdapString(request.getDnsHostName()));
			equalityMatchFilterBytes[0] = (byte) (ASN1_CONTEXT_SPECIFIC_TAG
					| ASN1_CONSTRUCTED_TAG
					| ASN1_LDAP_MESSAGE_SEARCH_REQUEST_EQUALITY_MATCH_FILTER_TAG_NUMBER);
			andFilterTerms.add(equalityMatchFilterBytes);
		}

		// Filter:and
		byte[] andFilterBytes = writeSequence(andFilterTerms.toArray(new byte[0][]));
		andFilterBytes[0] = (byte) (ASN1_CONTEXT_SPECIFIC_TAG
				| ASN1_CONSTRUCTED_TAG
				| ASN1_LDAP_MESSAGE_SEARCH_REQUEST_AND_FILTER_TAG_NUMBER);

		// SearchRequest
		byte[] searchRequestBytes = writeSequence(
				// baseObject
				writeLdapString(""),
				// scope
				ASN1_ENUMERATED_ZERO_BYTES,
				// derefAliases
				ASN1_ENUMERATED_ZERO_BYTES,
				// sizeLimit
				ASN1_INTEGER_ZERO_BYTES,
				// timeLimit
				ASN1_INTEGER_ZERO_BYTES,
				// typesOnly
				ASN1_BOOLEAN_FALSE_BYTES,
				// filter (Filter)
				andFilterBytes,
				// attributes (AttributeSelection)
				writeSequence(writeLdapString(NETLOGON_LDAP_ATTRIBUTE)));
		searchRequestBytes[0] =
				ASN1_APPLICATION_TAG | ASN1_CONSTRUCTED_TAG | ASN1_LDAP_MESSAGE_SEARCH_REQUEST_TAG_NUMBER;

		// LDAPMessage
		byte[] ldapMessageBytes = writeSequence(
				// messageID
				ASN1_INTEGER_ONE_BYTES,
				// protocolOp (SearchRequest)
				searchRequestBytes);
		return ldapMessageBytes;
	}

	private byte[] asn1Decode(byte[] response) throws CommunicationException {
		byte[] netlogonBytes = null;
		try {
			Asn1Parser parser = new Asn1Parser(response);
			List<Object> searchResults = new ArrayList<>();
			while (!parser.eof()) {
				// LDAPMessage
				parser.parseTagSequence();
				parser.parseLength();
				// messageID
				parser.parseInt();
				// protocolOp
				int tag = parser.peekTag();
				parser.parseTag(tag);
				int tagNumber = tag & ~(ASN1_APPLICATION_TAG | ASN1_CONSTRUCTED_TAG);
				int length = parser.parseLength();
				byte[] value = new byte[length];
				parser.parseBytes(value);
				searchResults.add(tagNumber);
				searchResults.add(value);
				// controls are ignored
			}

			Iterator<Object> searchResultsIter = searchResults.iterator();
			boolean searchResultDoneFound = false;
			while (searchResultsIter.hasNext() && !searchResultDoneFound) {
				int tagNumber = (int) searchResultsIter.next();
				byte[] value = (byte[]) searchResultsIter.next();
				parser = new Asn1Parser(value);
				switch (tagNumber) {
						// SearchResultEntry
					case ASN1_LDAP_MESSAGE_SEARCH_RESULT_ENTRY_TAG_NUMBER:
						// objectName
						parser.parseOctetString();
						// PartialAttributeList
						parser.parseTagSequence();
						parser.parseFullLength();
						while (!parser.eof()) {
							// PartialAttribute
							parser.parseTagSequence();
							parser.parseFullLength();
							while (!parser.eof()) {
								// type
								byte[] typeBytes = parser.parseOctetString();
								String type = fromLdapString(typeBytes);
								boolean isNetlogon = type.equalsIgnoreCase(NETLOGON_LDAP_ATTRIBUTE);
								// vals
								parser.parseTag(ASN1_SET_TAG);
								parser.parseFullLength();
								while (!parser.eof()) {
									byte[] valBytes = parser.parseOctetString();
									if (isNetlogon) {
										if (netlogonBytes == null) netlogonBytes = valBytes;
										else LOGGER.fine("Ignoring additional Netlogon attribute value");
									}
								}
							}
						}
						break;
						// SearchResultDone:LDAPResult
					case ASN1_LDAP_MESSAGE_SEARCH_RESULT_DONE_TAG_NUMBER:
						// resultCode
						parser.parseTag(ASN1_ENUMERATED_TAG);
						int length = parser.parseLength();
						byte[] resultCodeBytes = new byte[length];
						parser.parseBytes(resultCodeBytes);
						// matchedDN
						parser.parseOctetString();
						// diagnosticMessage
						byte[] diagnosticMessageBytes = parser.parseOctetString();
						if (!Arrays.equals(resultCodeBytes, LDAP_MESSAGE_SEARCH_RESULT_CODE_SUCCESS_BYTES)) {
							String message = "LDAP operation was not successful";
							BigInteger resultCode = new BigInteger(resultCodeBytes);
							message += " (" + resultCode + ")";
							if (diagnosticMessageBytes.length > 0) {
								String diagnosticMessage = fromLdapString(diagnosticMessageBytes);
								message += ": " + diagnosticMessage;
							}
							throw new IllegalArgumentException(message);
						}
						// referral is ignored
						searchResultDoneFound = true;
						break;
					default:
						throw new IllegalArgumentException("Unsupported LDAP message protocol operation: " + tagNumber);
				}
			}

			if (!searchResultDoneFound)
				throw new IllegalArgumentException("LDAP response did not contain a successful result");

			// Asn1Parser throws IllegalArgumentException
		} catch (IllegalArgumentException e) {
			CommunicationException ne = new CommunicationException("Failed to decode LDAP response");
			ne.initCause(e);
			throw ne;
		}

		return netlogonBytes;
	}
}
