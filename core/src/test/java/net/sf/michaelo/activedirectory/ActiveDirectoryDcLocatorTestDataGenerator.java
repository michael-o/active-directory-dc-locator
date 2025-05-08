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
package net.sf.michaelo.activedirectory;

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
 * Test data generator for {@link ActiveDirectoryDcLocatorTester}. It reads a domain file ({@code /domains.txt}) from
 * the class path or a file system path from the arguments. The file contains one domain per line. Then it reads a
 * sites-per-domain file (<code>/sites-{domain}.txt</code>) from the class path or a file system path as a sibling to
 * the domains file. The file contains one site per line. The output is written to standard output.
 */
public class ActiveDirectoryDcLocatorTestDataGenerator {

	private static final String[] DNS_DOMAINS = {"", "${domain}", "DomainDnsZones.${domain}", "ForestDnsZones.${domain}"
	};
	private static final String[] FLAGS = {
		"",
		"DS_ONLY_LDAP_NEEDED",
		"DS_ONLY_LDAP_NEEDED",
		"DS_ONLY_LDAP_NEEDED|DS_TRY_NEXTCLOSEST_SITE",
		"DS_ONLY_LDAP_NEEDED|DS_IP_REQUIRED",
		"DS_ONLY_LDAP_NEEDED|DS_GC_SERVER_REQUIRED",
		"DS_ONLY_LDAP_NEEDED|DS_GC_SERVER_REQUIRED|DS_WRITABLE_REQUIRED",
		"DS_ONLY_LDAP_NEEDED|DS_GC_SERVER_REQUIRED|DS_TRY_NEXTCLOSEST_SITE",
		"DS_ONLY_LDAP_NEEDED|DS_GC_SERVER_REQUIRED|DS_IP_REQUIRED",
		"DS_GC_SERVER_REQUIRED",
		"DS_GC_SERVER_REQUIRED|DS_WRITABLE_REQUIRED",
		"DS_GC_SERVER_REQUIRED|DS_TRY_NEXTCLOSEST_SITE",
		"DS_GC_SERVER_REQUIRED|DS_IP_REQUIRED",
		"DS_WEB_SERVICE_REQUIRED",
		"DS_TIMESERV_REQUIRED",
		"DS_TIMESERV_REQUIRED|DS_WEB_SERVICE_REQUIRED",
		"DS_TIMESERV_REQUIRED|DS_WEB_SERVICE_REQUIRED|DS_IP_REQUIRED",
		"DS_DIRECTORY_SERVICE_REQUIRED|DS_WRITABLE_REQUIRED|DS_TRY_NEXTCLOSEST_SITE",
		"DS_PDC_REQUIRED",
		"DS_KDC_REQUIRED|DS_WRITABLE_REQUIRED",
		"DS_KDC_REQUIRED|DS_WRITABLE_REQUIRED|DS_TRY_NEXTCLOSEST_SITE",
		"DS_KDC_REQUIRED|DS_WRITABLE_REQUIRED|DS_KEY_LIST_SUPPORT_REQUIRED",
		"DS_DIRECTORY_SERVICE_6_REQUIRED",
		"DS_DIRECTORY_SERVICE_8_REQUIRED",
		"DS_DIRECTORY_SERVICE_9_REQUIRED",
		"DS_DIRECTORY_SERVICE_10_REQUIRED"
	};

	private static final String[] RETURN_STYLES = {"DS_RETURN_DNS_NAME", "DS_RETURN_FLAT_NAME"};

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
			Path sitesFile = null;
			if (domainsFile.getFileSystem().equals(FileSystems.getDefault())) {
				sitesFile = domainsFile.resolveSibling("sites-" + domain + ".txt");
				if (Files.notExists(sitesFile)) {
					System.err.println("Domain sites file '" + sitesFile + "' does not exist");
					System.exit(1);
				}
			} else {
				URL sitesClasspathUrl =
						ActiveDirectoryDnsLocatorTestDataGenerator.class.getResource("/sites-" + domain + ".txt");
				if (sitesClasspathUrl == null) {
					System.err.println("Domain sites classpath resource '/sites-" + domain + ".txt' does not exist");
					System.exit(1);
				}
				sitesFile = Paths.get(sitesClasspathUrl.toURI());
			}

			for (String dnsDomain : DNS_DOMAINS) {
				dnsDomain = dnsDomain.replace("${domain}", domain);
				for (String site : Files.readAllLines(sitesFile)) {
					for (String flags : FLAGS) {
						if (flags.contains("DS_TRY_NEXTCLOSEST_SITE") && StringUtils.isNotEmpty(site)) continue;

						if (dnsDomain.contains("Zones")
								&& (!flags.contains("DS_ONLY_LDAP_NEEDED") || flags.contains("DS_GC_SERVER_REQUIRED")))
							continue;

						for (String returnStyle : RETURN_STYLES) {
							System.out.printf(
									"%s;%s;%s;%s%n",
									domain, dnsDomain, site, flags.isEmpty() ? returnStyle : flags + "|" + returnStyle);
						}
					}
				}
			}
		}
	}
}
