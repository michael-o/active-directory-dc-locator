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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import net.sf.michaelo.activedirectory.IntFlag;
import net.sf.michaelo.dirctxsrc.DirContextSource;

/**
 * Tester for {@link ActiveDirectoryLdapPinger}. Consumes data produced by
 * {@link ActiveDirectoryLdapPingerTestDataGenerator} from arguments and writes result to standard output.
 *
 * <p>The following system properties can be passed to the JVM:
 *
 * <ul>
 *   <li>{@code threads}: Amount of threads running in parallel with LDAP ping requests. Default is 1
 *   <li>{@code protocol}: Protocol to perform LDAP ping request, either {@code tcp} or {@code udp}. Default is
 *       {@code udp}
 *   <li>{@code pingType}: Whether LDAP ping will be sent by {@code plain} (raw) means or via {@code JNDI} (LDAP).
 *       Default is {@code plain}
 *   <li>{@code connectTimeout}: Time in milliseconds to wait for a DC to connect (TCP only). Default is 1000
 *   <li>{@code readTimeout}: Time in milliseconds to wait for a DC to respond. Default is 1000
 *   <li>{@code pollTimeout}: Time in milliseconds to wait for a thread to complete. Default is 5000
 * </ul>
 */
public class ActiveDirectoryLdapPingerTester {

	private static class LdapPingTask implements Callable<String> {

		private LdapPingRequest request;
		private String pingType;
		private String responseLine;

		private LdapPingTask(LdapPingRequest request, String pingType, String responseLine) {
			this.request = request;
			this.pingType = pingType;
			this.responseLine = responseLine;
		}

		@Override
		public String call() throws Exception {
			try {
				byte[] netlogonBytes = pingType.equalsIgnoreCase("plain") ? plainPing(request) : jndiPing(request);
				if (netlogonBytes != null)
					responseLine += "base64:" + Base64.getEncoder().encodeToString(netlogonBytes);
			} catch (Exception e) {
				responseLine += "exception:" + e;
			}

			return responseLine;
		}
	}

	private static final String NETLOGON_LDAP_ATTRIBUTE = "Netlogon";

	public static void main(String[] args) throws IOException, NamingException {
		if (args.length == 0) {
			System.err.println("No arguments provided");
			System.exit(1);
		}
		Path testDataFile = Paths.get(args[0]);
		if (Files.notExists(testDataFile)) {
			System.err.println("Test data file '" + testDataFile + "' does not exist");
			System.exit(1);
		}

		String[] dnsHostNames = {"", getFullyQualifiedLocalHostName()};

		ExecutorService executorService = Executors.newFixedThreadPool(Integer.getInteger("threads", 1));
		CompletionService<String> completionService = new ExecutorCompletionService<String>(executorService);
		List<Future<String>> futures = new ArrayList<>();

		try (Stream<String> lines = Files.lines(testDataFile)) {
			Iterator<String> iter = lines.iterator();
			while (iter.hasNext()) {
				String[] cols = iter.next().split(";");
				String domain = cols[0];
				String host = cols[1];
				String dnsDomain = cols[2];
				String ntVersionStr = cols[3];
				Set<NetlogonNtVersion> ntVersion = IntFlag.fromFlagsString(NetlogonNtVersion.class, ntVersionStr);

				for (String dnsHostName : dnsHostNames) {
					LdapPingRequest request = new LdapPingRequest(host, ntVersion);
					request.setProtocol(System.getProperty("protocol", "udp"));
					request.setDnsDomain(dnsDomain);
					request.setDnsHostName(dnsHostName);
					request.setConnectTimeout(Integer.getInteger("connectTimeout", 1000));
					request.setReadTimeout(Integer.getInteger("readTimeout", 1000));
					String pingType = System.getProperty("pingType", "plain");
					String responseLine =
							String.format("%s;%s;%s;%s;%s;", domain, host, dnsDomain, dnsHostName, ntVersionStr);

					futures.add(completionService.submit(new LdapPingTask(request, pingType, responseLine)));
				}
			}
		}

		while (true) {
			try {
				Future<String> future =
						completionService.poll(Integer.getInteger("pollTimeout", 5000), TimeUnit.MILLISECONDS);
				if (future != null) {
					String result = future.get();
					futures.remove(future);
					System.out.println(result);
				}

				if (futures.isEmpty()) break;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		executorService.shutdown();
	}

	private static byte[] jndiPing(LdapPingRequest request) throws NamingException {
		if (!request.getProtocol().equalsIgnoreCase("tcp")) return null;

		DirContextSource contextSource = new DirContextSource.Builder("ldap://" + request.getHostName())
				.debug(false)
				.derefAliases("never")
				.version(3)
				.binaryAttributes(NETLOGON_LDAP_ATTRIBUTE)
				.referral("throw")
				.connectTimeout(request.getConnectTimeout())
				.readTimeout(request.getReadTimeout())
				.build();

		DirContext ctx = contextSource.getDirContext();
		SearchControls ctls = new SearchControls();
		ctls.setSearchScope(SearchControls.OBJECT_SCOPE);
		ctls.setReturningAttributes(new String[] {NETLOGON_LDAP_ATTRIBUTE});
		byte[] ntVersionBytes = ByteBuffer.allocate(4)
				.order(ByteOrder.LITTLE_ENDIAN)
				.putInt(IntFlag.toFlags(request.getNtVersion()))
				.array();
		int idx = 0;
		StringBuilder filterExpr = new StringBuilder("(&");
		List<Object> filterArgs = new ArrayList<>();
		filterExpr.append("(NtVer={").append(idx++).append("})");
		filterArgs.add(ntVersionBytes);
		if (!request.getDnsDomain().isEmpty()) {
			filterExpr.append("(DnsDomain={").append(idx++).append("})");
			filterArgs.add(request.getDnsDomain());
		}
		if (!request.getDnsHostName().isEmpty()) {
			filterExpr.append("(DnsHostName={").append(idx++).append("})");
			filterArgs.add(request.getDnsHostName());
		}
		filterExpr.append(")");

		NamingEnumeration<SearchResult> search =
				ctx.search("", filterExpr.toString(), filterArgs.toArray(new Object[0]), ctls);

		byte[] netlogonBytes = null;
		while (search.hasMore()) {
			SearchResult result = search.next();
			if (netlogonBytes == null)
				netlogonBytes = (byte[])
						result.getAttributes().get(NETLOGON_LDAP_ATTRIBUTE).get();
			else {
				// TODO log duplicate/ignore
			}
		}

		search.close();
		ctx.close();

		return netlogonBytes;
	}

	private static byte[] plainPing(LdapPingRequest request) throws NamingException {
		ActiveDirectoryLdapPinger pinger = new ActiveDirectoryLdapPinger();
		return pinger.pingBytes(request);
	}

	private static String getFullyQualifiedLocalHostName() throws UnknownHostException {
		InetAddress localHost = InetAddress.getLocalHost();
		String hostName = localHost.getHostName();
		if (!hostName.contains(".")) {
			hostName = localHost.getCanonicalHostName();
		}

		return hostName;
	}
}
