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
package net.sf.michaelo.activedirectory.dns;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Test data generator for {@link ActiveDirectoryDnsLocatorTester}. It reads a domain file ({@code /domains.txt}) from
 * the class path or any path from arguments. The file contains one domain per line. The output is written to standard
 * output.
 */
public class ActiveDirectoryDnsLocatorTestDataGenerator {

	private static final String[] SERVICES = {"ldap", "kerberos", "kpasswd", "gc"};
	private static final String[] PROTOCOLS = {"", "tcp", "udp"};
	private static final String[] DC_TYPES = {"", "dc", "gc", "pdc"};
	private static final String[] DNS_DOMAINS = {"${domain}", "DomainDnsZones.${domain}", "ForestDnsZones.${domain}"};

	public static void main(String[] args) throws URISyntaxException, IOException {
		Path domainsFile = null;
		if (args.length > 0) {
			domainsFile = Paths.get(args[0]);
			if (Files.notExists(domainsFile)) {
				System.err.println("Domains file '" + domainsFile + "' does not exist");
				System.exit(1);
			}
		} else {
			URL domainsClasspathUrl = ActiveDirectoryDnsLocatorTestDataGenerator.class.getResource("/domains.txt");
			if (domainsClasspathUrl == null) {
				System.err.println("domains classpath resource '/domains.txt' does not exist");
				System.exit(1);
			}
			domainsFile = Paths.get(domainsClasspathUrl.toURI());
		}

		List<String> domains = Files.readAllLines(domainsFile);

		for (String service : SERVICES) {
			for (String protocol : PROTOCOLS) {
				for (String dcType : DC_TYPES) {
					for (String domain : domains) {
						for (String dnsDomain : DNS_DOMAINS) {
							String domainName = dnsDomain.replace("${domain}", domain);
							System.out.printf("%s;%s;;%s;%s%n", service, protocol, dcType, domainName);
						}
					}
				}
			}
		}
	}
}
