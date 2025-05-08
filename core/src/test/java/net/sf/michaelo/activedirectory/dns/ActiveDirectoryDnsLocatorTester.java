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
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.naming.NamingException;

/**
 * Tester for {@link ActiveDirectoryDnsLocator}. Consumes data produced by
 * {@link ActiveDirectoryDnsLocatorTestDataGenerator} from arguments and writes result to standard output.
 *
 * <p>The following system properties can be passed to the JVM:
 *
 * <ul>
 *   <li>{@code threads}: Amount of threads running in parallel with DNS requests. Default is 1
 *   <li>{@code readTimeout}: Time in milliseconds to wait for a DNS server to respond. Default is 1000
 *   <li>{@code pollTimeout}: Time in milliseconds to wait for a thread to complete. Default is 5000
 * </ul>
 */
public class ActiveDirectoryDnsLocatorTester {

	private static class DnsLocatorTask implements Callable<String> {

		private ActiveDirectoryDnsLocator locator;
		private DnsLocatorRequest request;
		private String responseLine;

		private DnsLocatorTask(ActiveDirectoryDnsLocator locator, DnsLocatorRequest request, String responseLine) {
			this.locator = locator;
			this.request = request;
			this.responseLine = responseLine;
		}

		@Override
		public String call() throws Exception {
			try {
				InetSocketAddress[] hosts = locator.locate(request);
				responseLine += Arrays.toString(hosts);
			} catch (NamingException e) {
				responseLine += "exception:" + e;
			}

			return responseLine;
		}
	}

	public static void main(String[] args) throws IOException {
		if (args.length == 0) {
			System.err.println("No arguments provided");
			System.exit(1);
		}
		Path testDataFile = Paths.get(args[0]);
		if (Files.notExists(testDataFile)) {
			System.err.println("Test data file '" + testDataFile + "' does not exist");
			System.exit(1);
		}

		ActiveDirectoryDnsLocator locator = new ActiveDirectoryDnsLocator.Builder()
				.readTimeout(Integer.getInteger("readTimeout", 1000))
				.build();
		ExecutorService executorService = Executors.newFixedThreadPool(Integer.getInteger("threads", 1));
		CompletionService<String> completionService = new ExecutorCompletionService<String>(executorService);
		List<Future<String>> futures = new ArrayList<>();

		try (Stream<String> lines = Files.lines(testDataFile)) {
			lines.forEach(line -> {
				String[] cols = line.split(";");
				String service = cols[0];
				String protocol = cols[1];
				String siteName = cols[2];
				String dcType = cols[3];
				String domainName = cols[4];

				DnsLocatorRequest request = new DnsLocatorRequest(service, domainName);
				request.setProtocol(protocol);
				request.setSiteName(siteName);
				request.setDcType(dcType);
				String responseLine = String.format("%s;%s;%s;%s;%s;", service, protocol, siteName, dcType, domainName);

				futures.add(completionService.submit(new DnsLocatorTask(locator, request, responseLine)));
			});
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
}
