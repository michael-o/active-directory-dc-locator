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
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import net.sf.michaelo.activedirectory.dns.ActiveDirectoryDnsLocatorTestDataGenerator;

/**
 * Test data generator for {@link ActiveDirectoryLdapPingerTester}. It reads a domain file ({@code /domains.txt}) from
 * the class path or a file system path from arguments. The file contains one domain per line. Then it reads a
 * hosts-per-domain file (<code>/hosts-{domain}.txt</code>) from the class path or a file system path as a sibling to
 * the domains file. The file contains one host per line. The output is written to standard output.
 */
public class ActiveDirectoryLdapPingerTestDataGenerator {

	private static final String[] DNS_DOMAINS = {
		"", "bogus", "${domain}", "DomainDnsZones.${domain}", "ForestDnsZones.${domain}"
	};
	private static final String[] NT_VERSIONS = {
		"V1",
		"V1|V5",
		"V1|V5EX",
		"V1|V5EX|VPDC",
		"V1|V5EX|VGC",
		"V1|V5EX|V5EP",
		"V1|V5EX|VCS",
		"V1|V5EX|V5EP|VCS",
		"V1|V5EX|V5EP|VCS|VGC"
	};

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
				System.err.println("Domains classpath resource '/domains.txt' does not exist");
				System.exit(1);
			}
			domainsFile = Paths.get(domainsClasspathUrl.toURI());
		}

		List<String> domains = Files.readAllLines(domainsFile);

		for (String domain : domains) {
			Path hostsFile = null;
			if (domainsFile.getFileSystem().equals(FileSystems.getDefault())) {
				hostsFile = domainsFile.resolveSibling("hosts-" + domain + ".txt");
				if (Files.notExists(hostsFile)) {
					System.err.println("Domain hosts file '" + hostsFile + "' does not exist");
					System.exit(1);
				}
			} else {
				URL hostsClasspathUrl =
						ActiveDirectoryDnsLocatorTestDataGenerator.class.getResource("/hosts-" + domain + ".txt");
				if (hostsClasspathUrl == null) {
					System.err.println("Domain hosts classpath resource '/hosts-" + domain + ".txt' does not exist");
					System.exit(1);
				}
				hostsFile = Paths.get(hostsClasspathUrl.toURI());
			}

			for (String host : Files.readAllLines(hostsFile)) {
				for (String dnsDomain : DNS_DOMAINS) {
					String domainName = dnsDomain.replace("${domain}", domain);
					for (String ntVersion : NT_VERSIONS) {
						System.out.printf("%s;%s;%s;%s%n", domain, host, domainName, ntVersion);
					}
				}
			}
		}
	}
}
