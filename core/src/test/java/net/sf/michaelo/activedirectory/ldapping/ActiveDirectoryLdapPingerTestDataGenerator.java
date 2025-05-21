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
 * hostnames-per-domain file (<code>/hostnames-{domain}.txt</code>) from the class path or a file system path as a
 * sibling to the domains file. The file contains one host name per line. The output is written to standard output.
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
			Path hostNamesFile = null;
			if (domainsFile.getFileSystem().equals(FileSystems.getDefault())) {
				hostNamesFile = domainsFile.resolveSibling("hostnames-" + domain + ".txt");
				if (Files.notExists(hostNamesFile)) {
					System.err.println("Domain host names file '" + hostNamesFile + "' does not exist");
					System.exit(1);
				}
			} else {
				URL hostNamesClasspathUrl =
						ActiveDirectoryDnsLocatorTestDataGenerator.class.getResource("/hostnames-" + domain + ".txt");
				if (hostNamesClasspathUrl == null) {
					System.err.println(
							"Domain host names classpath resource '/hostnames-" + domain + ".txt' does not exist");
					System.exit(1);
				}
				hostNamesFile = Paths.get(hostNamesClasspathUrl.toURI());
			}

			for (String hostName : Files.readAllLines(hostNamesFile)) {
				for (String dnsDomain : DNS_DOMAINS) {
					String domainName = dnsDomain.replace("${domain}", domain);
					for (String ntVersion : NT_VERSIONS) {
						System.out.printf("%s;%s;%s;%s%n", domain, hostName, domainName, ntVersion);
					}
				}
			}
		}
	}
}
