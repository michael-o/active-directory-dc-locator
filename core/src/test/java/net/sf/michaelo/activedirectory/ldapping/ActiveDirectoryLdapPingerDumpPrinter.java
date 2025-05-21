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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import net.sf.michaelo.activedirectory.IntFlag;

/**
 * An LDAP ping {@code NetlogonSamLogonBaseResponse} subclasses dump printer produced by
 * {@link ActiveDirectoryLdapPingerTester}.
 *
 * <p>This class can be called via its main method, it supports the following optional parameters:
 *
 * <ul>
 *   <li>output format {@code --format} {@code listing} (default) or {@code sql},
 * </ul>
 *
 * <p>and the following positional parameters:
 *
 * <ul>
 *   <li>dump file {@code path...}: a file containing dumps.
 * </ul>
 *
 * <p>The {@code sql} format output can be used to import the data into a SQLite database for later analysis.
 */
public class ActiveDirectoryLdapPingerDumpPrinter {

	private static final AtomicInteger NETLOGON_ID_GENERATOR = new AtomicInteger();

	private static void dumpFile(Path file, String format) throws IOException {
		System.err.printf("Processing file '%s'%n", file);

		try (Stream<String> lines = Files.lines(file)) {
			Iterator<String> iter = lines.iterator();
			while (iter.hasNext()) {
				String[] cols = iter.next().split(";", 6);
				String domain = cols[0];
				String hostName = cols[1];
				String dnsDomain = cols[2];
				String dnsHostName = cols[3];
				String ntVersionStr = cols[4];
				Set<NetlogonNtVersion> ntVersion = IntFlag.fromFlagsString(NetlogonNtVersion.class, ntVersionStr);
				String output = cols[5];

				int requestId = NETLOGON_ID_GENERATOR.incrementAndGet();

				switch (format) {
					case "listing":
						System.out.println("Request:");
						System.out.println("  domain: " + domain);
						System.out.println("  host name: " + hostName);
						if (!dnsDomain.isEmpty()) System.out.println("  dnsDomain: " + dnsDomain);
						if (!dnsHostName.isEmpty()) System.out.println("  dnsHostName: " + dnsHostName);
						System.out.println("  ntVersion: " + ntVersionStr);
						break;
					case "sql":
						System.out.printf(
								"insert into netlogon_request(id, domain, hostName, dnsDomain, dnsHostName, ntVersion)"
										+ " values(%d, '%s', '%s', %s, %s, '%s');%n",
								requestId, domain, hostName, nullSafe(dnsDomain), nullSafe(dnsHostName), ntVersionStr);
						break;
				}

				switch (format) {
					case "listing":
						System.out.println("Response:");
						break;
					case "sql":
						System.out.printf(
								"insert into netlogon_response_info(requestId, responseType, exception)"
										+ " values(%d, ",
								requestId);
						break;
				}
				if (output.isEmpty()) {
					switch (format) {
						case "listing":
							System.out.println("  (none)");
							break;
						case "sql":
							System.out.println("NULL, NULL);");
							break;
					}
				} else {
					if (output.startsWith("exception:")) {
						String exception = output.substring("exception:".length());
						switch (format) {
							case "listing":
								System.out.println("  " + exception);
								break;
							case "sql":
								System.out.printf("NULL, '%s');%n", exception);
								break;
						}
					} else {
						byte[] netlogon = Base64.getDecoder().decode(output.substring("base64:".length()));

						if (ntVersion.contains(NetlogonNtVersion.V5EX)) {
							NetlogonSamLogonExResponse response = new NetlogonSamLogonExResponse(netlogon);
							switch (format) {
								case "listing":
									System.out.println("  NetlogonSamLogonExResponse:");
									break;
								case "sql":
									System.out.println("'NETLOGON_SAM_LOGON_RESPONSE_EX', NULL);");
									break;
							}
							Opcode opcode = response.getOpcode();
							String opcodeStr = String.valueOf(opcode);
							Set<DsFlag> flags = response.getFlags();
							String flagsStr = IntFlag.toFlagsString(flags);
							UUID domainGuid = response.getDomainGuid();
							String dnsForestName = response.getDnsForestName();
							String dnsDomainName = response.getDnsDomainName();
							dnsHostName = response.getDnsHostName();
							String netbiosDomainName = response.getNetbiosDomainName();
							String netbiosComputerName = response.getNetbiosComputerName();
							String userName = response.getUserName();
							String dcSiteName = response.getDcSiteName();
							String clientSiteName = response.getClientSiteName();
							String dcSockAddr = response.getDcSockAddr() != null
									? response.getDcSockAddr().getHostAddress()
									: null;
							String nextClosestSiteName = response.getNextClosestSiteName();
							ntVersion = response.getNtVersion();
							ntVersionStr = IntFlag.toFlagsString(ntVersion);
							switch (format) {
								case "listing":
									System.out.println("    opcode: " + opcodeStr);
									System.out.println("    flags: " + flagsStr);
									System.out.println("    domainGuid: " + domainGuid);
									System.out.println("    dnsForestName: " + dnsForestName);
									System.out.println("    dnsDomainName: " + dnsDomainName);
									System.out.println("    dnsHostName: " + dnsHostName);
									if (netbiosDomainName != null)
										System.out.println("    netbiosDomainName: " + netbiosDomainName);
									if (netbiosComputerName != null)
										System.out.println("    netbiosComputerName: " + netbiosComputerName);
									if (userName != null) System.out.println("    userName: " + userName);
									System.out.println("    dcSiteName: " + dcSiteName);
									if (clientSiteName != null)
										System.out.println("    clientSiteName: " + clientSiteName);
									if (dcSockAddr != null) System.out.println("    dcSockAddr: " + dcSockAddr);
									if (nextClosestSiteName != null)
										System.out.println("    nextClosestSiteName: " + nextClosestSiteName);
									System.out.println("    ntVersion: " + ntVersionStr);
									break;
								case "sql":
									System.out.printf(
											"insert into netlogon_sam_logon_ex_response(requestId, opcode, flags, domainGuid,"
													+ " dnsForestName, dnsDomainName, dnsHostName, netbiosDomainName, netbiosComputerName,"
													+ " userName, dcSiteName, clientSiteName, dcSockAddr, nextClosestSiteName, ntVersion)"
													+ " values(%d, '%s', '%s', '%s', '%s', '%s', '%s', %s, %s, %s, '%s', %s, %s, %s, '%s');%n",
											requestId,
											opcodeStr,
											flagsStr,
											domainGuid,
											dnsForestName,
											dnsDomainName,
											dnsHostName,
											nullSafe(netbiosDomainName),
											nullSafe(netbiosComputerName),
											nullSafe(userName),
											dcSiteName,
											nullSafe(clientSiteName),
											nullSafe(dcSockAddr),
											nullSafe(nextClosestSiteName),
											ntVersionStr);
									break;
							}

						} else if (ntVersion.contains(NetlogonNtVersion.V5)) {
							NetlogonSamLogonResponse response = new NetlogonSamLogonResponse(netlogon);
							switch (format) {
								case "listing":
									System.out.println("  NetlogonSamLogonResponse:");
									break;
								case "sql":
									System.out.println("'NETLOGON_SAM_LOGON_RESPONSE', NULL);");
									break;
							}
							Opcode opcode = response.getOpcode();
							String opcodeStr = String.valueOf(opcode);
							String unicodeLogonServer = response.getUnicodeLogonServer();
							String unicodeUserName = response.getUnicodeUserName();
							String unicodeDomainName = response.getUnicodeDomainName();
							UUID domainGuid = response.getDomainGuid();
							String dnsForestName = response.getDnsForestName();
							String dnsDomainName = response.getDnsDomainName();
							dnsHostName = response.getDnsHostName();
							String dcIpAddress = response.getDcIpAddress().getHostAddress();
							Set<DsFlag> flags = response.getFlags();
							String flagsStr = IntFlag.toFlagsString(flags);
							ntVersion = response.getNtVersion();
							ntVersionStr = IntFlag.toFlagsString(ntVersion);
							switch (format) {
								case "listing":
									System.out.println("    opcode: " + opcodeStr);
									if (unicodeLogonServer != null)
										System.out.println("    unicodeLogonServer: " + unicodeLogonServer);
									if (unicodeUserName != null)
										System.out.println("    unicodeUserName: " + unicodeUserName);
									if (unicodeDomainName != null)
										System.out.println("    unicodeDomainName: " + unicodeDomainName);
									System.out.println("    domainGuid: " + domainGuid);
									System.out.println("    dnsForestName: " + dnsForestName);
									System.out.println("    dnsDomainName: " + dnsDomainName);
									System.out.println("    dnsHostName: " + dnsHostName);
									System.out.println("    dcIpAddress: " + dcIpAddress);
									System.out.println("    flags: " + flagsStr);
									System.out.println("    ntVersion: " + ntVersionStr);
									break;
								case "sql":
									System.out.printf(
											"insert into netlogon_sam_logon_response(requestId, opcode, unicodeLogonServer, unicodeUserName,"
													+ " unicodeDomainName, domainGuid, dnsForestName, dnsDomainName, dnsHostName,"
													+ " dcIpAddress, flags, ntVersion)"
													+ " values(%d, '%s', %s, %s, %s, '%s', '%s', '%s', '%s', '%s', '%s', '%s');%n",
											requestId,
											opcodeStr,
											nullSafe(unicodeLogonServer),
											nullSafe(unicodeUserName),
											nullSafe(unicodeDomainName),
											domainGuid,
											dnsForestName,
											dnsDomainName,
											dnsHostName,
											dcIpAddress,
											flagsStr,
											ntVersionStr);
									break;
							}
						} else {
							NetlogonSamLogonNt40Response response = new NetlogonSamLogonNt40Response(netlogon);
							switch (format) {
								case "listing":
									System.out.println("  NetlogonSamLogonNt40Response:");
									break;
								case "sql":
									System.out.println("'NETLOGON_SAM_LOGON_RESPONSE_NT40', NULL);");
									break;
							}
							Opcode opcode = response.getOpcode();
							String opcodeStr = String.valueOf(opcode);
							String unicodeLogonServer = response.getUnicodeLogonServer();
							String unicodeUserName = response.getUnicodeUserName();
							String unicodeDomainName = response.getUnicodeDomainName();
							ntVersion = response.getNtVersion();
							ntVersionStr = IntFlag.toFlagsString(ntVersion);
							switch (format) {
								case "listing":
									System.out.println("    opcode: " + opcodeStr);
									if (unicodeLogonServer != null)
										System.out.println("    unicodeLogonServer: " + unicodeLogonServer);
									if (unicodeUserName != null)
										System.out.println("    unicodeUserName: " + unicodeUserName);
									if (unicodeDomainName != null)
										System.out.println("    unicodeDomainName: " + unicodeDomainName);
									System.out.println("    ntVersion: " + ntVersionStr);
									break;
								case "sql":
									System.out.printf(
											"insert into netlogon_sam_logon_nt40_response(requestId, opcode, unicodeLogonServer, unicodeUserName,"
													+ " unicodeDomainName, ntVersion)"
													+ " values(%d, '%s', %s, %s, %s, '%s');%n",
											requestId,
											opcodeStr,
											nullSafe(unicodeLogonServer),
											nullSafe(unicodeUserName),
											nullSafe(unicodeDomainName),
											ntVersionStr);
									break;
							}
						}
					}
				}
			}
		}
	}

	private static String nullSafe(String str) {
		return str != null && !str.isEmpty() ? "'" + str + "'" : "NULL";
	}

	public static void main(String[] args) throws IOException, SignatureException {
		if (args.length == 0) {
			System.err.println("No arguments provided");
			System.exit(1);
		}

		int positionalArgs = 0;
		String formatValue = "listing";
		boolean breakLoop = false;
		while (positionalArgs < args.length && !breakLoop) {
			switch (args[positionalArgs]) {
				case "--format":
					positionalArgs++;
					if (positionalArgs > args.length - 1)
						throw new IllegalArgumentException("Missing option value for '--format'");
					formatValue = args[positionalArgs++];
					break;
				case "--":
					positionalArgs++;
					breakLoop = true;
					break;
				default:
					breakLoop = true;
					break;
			}
		}

		if (!formatValue.equals("listing") && !formatValue.equals("sql"))
			throw new IllegalArgumentException("Unsupported format value: " + formatValue);

		final String format = formatValue;
		if (format.equals("sql")) {
			System.out.println("BEGIN TRANSACTION;");
			try (BufferedReader r = new BufferedReader(new InputStreamReader(
					ActiveDirectoryLdapPingerDumpPrinter.class.getResourceAsStream(
							"/net/sf/michaelo/activedirectory/ldapping/create-tables.sql"),
					StandardCharsets.UTF_8))) {
				r.lines().forEach(line -> System.out.println(line));
			}
		}

		for (int i = positionalArgs; i < args.length; i++) {
			Path path = Paths.get(args[i]);
			if (Files.notExists(path)) {
				System.err.printf("Ignoring non-existing path '%s'%n", path);
				continue;
			}
			if (Files.isRegularFile(path)) {
				dumpFile(path, format);
			} else if (Files.isDirectory(path)) {
				Files.walk(path).filter(Files::isRegularFile).forEach(file -> {
					try {
						dumpFile(file, format);
					} catch (IOException e) {
						throw new UncheckedIOException(e);
					}
				});
			} else {
				System.err.printf("Ignoring unsupported path '%s'%n", path);
				continue;
			}
		}

		if (format.equals("sql")) {
			System.out.println("COMMIT;");
		}
	}
}
