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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
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

import javax.naming.NamingException;

import net.sf.michaelo.activedirectory.DcLocatorRequest.Flag;

/**
 * Tester for {@link ActiveDirectoryDcLocator}. Consumes data produced by
 * {@link ActiveDirectoryDcLocatorTestDataGenerator} from arguments and writes result to standard output.
 *
 * <p>The following system properties can be passed to the JVM:
 *
 * <ul>
 *   <li>{@code threads}: Amount of threads running in parallel with DC locator requests. Default is 1
 *   <li>{@code readTimeout}: Time in milliseconds to wait for a DC to respond. Default is 1000
 *   <li>{@code pollTimeout}: Time in milliseconds to wait for a thread to complete. Default is 5000
 * </ul>
 */
public class ActiveDirectoryDcLocatorTester {

	private static class DcLocatorTask implements Callable<String> {

		private DcLocatorRequest request;
		private String responseLine;

		private DcLocatorTask(DcLocatorRequest request, String responseLine) {
			this.request = request;
			this.responseLine = responseLine;
		}

		@Override
		public String call() throws Exception {
			try {
				ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();
				DomainControllerInfo dcInfo = locator.locate(request);
				responseLine += dcInfo;
			} catch (Exception e) {
				responseLine += "exception:" + e;
			}

			return responseLine;
		}
	}

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

		String localHostName = getFullyQualifiedLocalHostName();

		ExecutorService executorService = Executors.newFixedThreadPool(Integer.getInteger("threads", 1));
		CompletionService<String> completionService = new ExecutorCompletionService<String>(executorService);
		List<Future<String>> futures = new ArrayList<>();

		try (Stream<String> lines = Files.lines(testDataFile)) {
			lines.forEach(line -> {
				String[] cols = line.split(";");
				String domain = cols[0];
				String dnsDomain = cols[1];
				String site = cols[2];
				String flagsStr = cols[3];
				Set<Flag> flags = IntFlag.fromFlagsString(Flag.class, flagsStr);

				if (StringUtils.isNotEmpty(site) && StringUtils.isEmpty(dnsDomain) && !localHostName.endsWith(domain)) {
					System.out.printf("%s;%s;%s;%s;skipped:%n", domain, dnsDomain, site, flagsStr);
					return;
				}

				DcLocatorRequest request = new DcLocatorRequest();
				request.setDomainName(dnsDomain);
				request.setSiteName(site);
				flags.forEach(f -> request.addFlag(f));
				request.setReadTimeout(Integer.getInteger("readTimeout", 1000));
				String responseLine = String.format("%s;%s;%s;%s;", domain, dnsDomain, site, flagsStr);

				futures.add(completionService.submit(new DcLocatorTask(request, responseLine)));
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

	private static String getFullyQualifiedLocalHostName() throws UnknownHostException {
		InetAddress localHost = InetAddress.getLocalHost();
		String hostName = localHost.getHostName();
		if (!hostName.contains(".")) {
			hostName = localHost.getCanonicalHostName();
		}

		return hostName;
	}
}
