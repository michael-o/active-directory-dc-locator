/*
 * Copyright 2016–2025 Michael Osipov
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

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Objects;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import net.sf.michaelo.activedirectory.StringUtils;

import org.apache.commons.lang3.Validate;

/**
 * A locator for various Active Directory services like LDAP, Global Catalog, Kerberos, etc. via DNS SRV resource
 * records. This is a lightweight implementation of <a href="https://www.rfc-editor.org/rfc/rfc2782.html">RFC 2782</a>
 * for the resource records depicted <a
 * href="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759550(v=ws.10)">here</a>.
 * The host selection algorithm for failover is fully implemented.
 *
 * <p>Here is a minimal example how to create an {@code ActiveDirectoryDnsLocator} with a supplied builder:
 *
 * <pre>
 * ActiveDirectoryDnsLocator.Builder builder = new ActiveDirectoryDnsLocator.Builder();
 * ActiveDirectoryDnsLocator locator = builder.build();
 * DnsLocatorRequest request = new DnsLocatorRequest("ldap", "ad.example.com");
 * InetSocketAddress[] hostAddresses = locator.locate(request);
 * </pre>
 *
 * An {@code ActiveDirectoryDnsLocator} object will be initially preconfigured by its builder for you:
 *
 * <ul>
 *   <li>The context factory is set by default to {@code com.sun.jndi.dns.DnsContextFactory}.
 * </ul>
 *
 * A complete overview of all {@code DirContext} properties can be found <a
 * href="https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-dns.html">here</a>. Make sure that you pass
 * reasonable/valid values only otherwise the behavior is undefined.
 *
 * <p><b>Note</b>: This class uses JUL to print log messages, enable at least level {@code FINE} to see output.
 */
public class ActiveDirectoryDnsLocator {

	private static final String DEFAULT_PROTOCOL = "tcp";

	private static class SrvRecord implements Comparable<SrvRecord> {

		static final String UNAVAILABLE_SERVICE = ".";

		private int priority;
		private int weight;
		private int sum;
		private int port;
		private String target;

		public SrvRecord(int priority, int weight, int port, String target) {
			Validate.inclusiveBetween(0, 0xFFFF, priority, "priority must be between 0 and 65535");
			Validate.inclusiveBetween(0, 0xFFFF, weight, "weight must be between 0 and 65535");
			Validate.inclusiveBetween(0, 0xFFFF, port, "port must be between 0 and 65535");
			Validate.notEmpty(target, "target cannot be null or empty");

			this.priority = priority;
			this.weight = weight;
			this.port = port;
			this.target = target;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof SrvRecord)) return false;

			SrvRecord that = (SrvRecord) obj;

			return priority == that.priority
					&& weight == that.weight
					&& port == that.port
					&& target.equals(that.target);
		}

		@Override
		public int hashCode() {
			return Objects.hash(priority, weight, port, target);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder("SrvRecord[");
			sb.append(priority).append(' ');
			sb.append(weight).append(' ');
			if (sum != 0) sb.append('(').append(sum).append(") ");
			sb.append(port).append(' ');
			sb.append(target);
			sb.append("]");
			return sb.toString();
		}

		@Override
		public int compareTo(SrvRecord that) {
			// Comparing according to the RFC
			if (priority > that.priority) {
				return 1;
			} else if (priority < that.priority) {
				return -1;
			} else if (weight == 0 && that.weight != 0) {
				return -1;
			} else if (weight != 0 && that.weight == 0) {
				return 1;
			} else {
				return 0;
			}
		}
	}

	private static final String SRV_RR = "SRV";
	private static final String[] SRV_RR_ATTR = new String[] {SRV_RR};

	private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryDnsLocator.class.getName());

	private final Hashtable<String, Object> env;

	private ActiveDirectoryDnsLocator(Builder builder) {
		env = new Hashtable<String, Object>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, builder.contextFactory);
		if (builder.readTimeout > 0) env.put("com.sun.jndi.dns.timeout.initial", String.valueOf(builder.readTimeout));
		env.putAll(builder.additionalProperties);
	}

	/**
	 * A builder to construct an {@link ActiveDirectoryDnsLocator} with a fluent interface.
	 *
	 * <p><strong>Notes:</strong>
	 *
	 * <ol>
	 *   <li>This class is not thread-safe. Configure a builder in your main thread, build the object and pass it on to
	 *       your forked threads.
	 *   <li>An {@code IllegalStateException} is thrown if a property is modified after this builder has already been
	 *       used to build an {@code ActiveDirectoryDnsLocator}, simply create a new builder in this case.
	 *   <li>All passed arrays will be defensively copied and null/empty values will be skipped except when all elements
	 *       are invalid, an exception will be raised.
	 * </ol>
	 */
	public static final class Builder {

		// Builder properties
		private String contextFactory;
		private int readTimeout = -1;
		private Hashtable<String, Object> additionalProperties;

		private boolean done;

		/** Constructs a new builder for {@link ActiveDirectoryDnsLocator}. */
		public Builder() {
			// Initialize default values first as mentioned in the class' Javadoc
			contextFactory("com.sun.jndi.dns.DnsContextFactory");
			additionalProperties = new Hashtable<String, Object>();
		}

		/**
		 * Sets the context factory for this service locator.
		 *
		 * @param contextFactory the context factory class name
		 * @throws NullPointerException if {@code contextFactory} is null
		 * @throws IllegalArgumentException if {@code contextFactory} is empty
		 * @return this builder
		 */
		public Builder contextFactory(String contextFactory) {
			check();
			this.contextFactory = validateAndReturnString("contextFactory", contextFactory);
			return this;
		}

		/**
		 * Sets the read timeout in milliseconds. This only works if the {@link #contextFactory(String)} is
		 * {@code com.sun.jndi.dns.DnsContextFactory}.
		 *
		 * @param readTimeout the read timeout in milliseconds
		 * @return this builder
		 */
		public Builder readTimeout(int readTimeout) {
			check();
			this.readTimeout = readTimeout;
			return this;
		}

		/**
		 * Sets an additional property not available through the builder interface.
		 *
		 * @param name name of the property
		 * @param value value of the property
		 * @throws NullPointerException if {@code name} is null
		 * @throws IllegalArgumentException if {@code name} is empty
		 * @return this builder
		 */
		public Builder additionalProperty(String name, Object value) {
			check();
			Validate.notEmpty(name, "Additional property's name cannot be null or empty");
			this.additionalProperties.put(name, value);
			return this;
		}

		/**
		 * Builds an {@code ActiveDirectoryDnsLocator} and marks this builder as non-modifiable for future use. You may
		 * call this method as often as you like, it will return a new {@code ActiveDirectoryDnsLocator} instance on
		 * every call.
		 *
		 * @throws IllegalStateException if a combination of necessary attributes is not set
		 * @return an {@code ActiveDirectoryDnsLocator} object
		 */
		public ActiveDirectoryDnsLocator build() {
			ActiveDirectoryDnsLocator serviceLocator = new ActiveDirectoryDnsLocator(this);
			done = true;

			return serviceLocator;
		}

		private void check() {
			if (done) throw new IllegalStateException("Cannot modify an already used builder");
		}

		private String validateAndReturnString(String name, String value) {
			return Validate.notEmpty(value, "Property name '%s' cannot be null or empty", name);
		}
	}

	private SrvRecord[] lookUpSrvRecords(DirContext context, String name) throws NamingException {
		Attributes attrs = context.getAttributes(name, SRV_RR_ATTR);

		Attribute srvAttr = attrs.get(SRV_RR);
		if (srvAttr == null) return new SrvRecord[0];

		NamingEnumeration<?> records = null;

		SrvRecord[] srvRecords = new SrvRecord[srvAttr.size()];

		try {
			records = srvAttr.getAll();

			int recordCnt = 0;
			while (records.hasMore()) {
				String record = (String) records.next();
				try (Scanner scanner = new Scanner(record)) {
					scanner.useDelimiter(" ");

					int priority = scanner.nextInt();
					int weight = scanner.nextInt();
					int port = scanner.nextInt();
					String target = scanner.next();
					SrvRecord srvRecord = new SrvRecord(priority, weight, port, target);

					srvRecords[recordCnt++] = srvRecord;
				}
			}
		} finally {
			if (records != null)
				try {
					records.close();
				} catch (NamingException e) {
					// ignore
				}
		}

		/*
		 * The DNS server explicitly indicating that this service is not provided as
		 * described by the RFC.
		 */
		if (srvRecords.length == 1 && srvRecords[0].target.equals(SrvRecord.UNAVAILABLE_SERVICE))
			return new SrvRecord[0];

		return srvRecords;
	}

	private InetSocketAddress[] sortByRfc2782(SrvRecord[] srvRecords) {
		// Apply the record selection algorithm
		Arrays.sort(srvRecords);

		InetSocketAddress[] sortedHostAddresses = new InetSocketAddress[srvRecords.length];
		for (int i = 0, start = -1, end = -1, hp = 0; i < srvRecords.length; i++) {

			start = i;
			while (i + 1 < srvRecords.length && srvRecords[i].priority == srvRecords[i + 1].priority) {
				i++;
			}
			end = i;

			for (int repeat = 0; repeat < (end - start) + 1; repeat++) {
				int sum = 0;
				for (int j = start; j <= end; j++) {
					if (srvRecords[j] != null) {
						sum += srvRecords[j].weight;
						srvRecords[j].sum = sum;
					}
				}

				int r = sum == 0 ? 0 : ThreadLocalRandom.current().nextInt(sum + 1);
				for (int k = start; k <= end; k++) {
					SrvRecord srvRecord = srvRecords[k];

					if (srvRecord != null && srvRecord.sum >= r) {
						String hostName = srvRecord.target.substring(0, srvRecord.target.length() - 1);
						sortedHostAddresses[hp++] = InetSocketAddress.createUnresolved(hostName, srvRecord.port);
						srvRecords[k] = null;
					}
				}
			}
		}

		return sortedHostAddresses;
	}

	/**
	 * Locates a desired service via DNS within an Active Directory domain, sorted and selected according to RFC 2782.
	 *
	 * @param request the DNS locator request
	 * @return the located host addresses, never null
	 * @throws NullPointerException if {@code request} is null
	 * @throws NamingException if an error has occurred while creating, querying the DNS directory context or processing
	 *     the resource records
	 * @throws InvalidNameException if the supplied domain name (labels) is invalid
	 * @throws NameNotFoundException if the supplied domain name has not been found
	 */
	public InetSocketAddress[] locate(DnsLocatorRequest request) throws NamingException {
		Objects.requireNonNull(request, "request cannot be null");

		DirContext context = null;
		try {
			context = new InitialDirContext(env);
		} catch (NamingException e) {
			NamingException ne = new NamingException("Failed to create DNS directory context");
			ne.initCause(e);
			throw ne;
		}

		StringBuilder lookupName = new StringBuilder();
		lookupName.append("_").append(request.getService());
		lookupName.append("._");
		if (StringUtils.isNotEmpty(request.getProtocol())) lookupName.append(request.getProtocol());
		else lookupName.append(DEFAULT_PROTOCOL);
		if (StringUtils.isNotEmpty(request.getSiteName()))
			lookupName.append(".").append(request.getSiteName()).append(".").append("_sites");
		if (StringUtils.isNotEmpty(request.getDcType()))
			lookupName.append(".").append(request.getDcType()).append(".").append("_msdcs");
		lookupName.append(".").append(request.getDomainName());

		SrvRecord[] srvRecords = null;
		try {
			LOGGER.fine(() -> String.format("Looking up SRV RRs for '%s'", lookupName));
			srvRecords = lookUpSrvRecords(context, lookupName.toString());
		} finally {
			try {
				context.close();
			} catch (NamingException e) {
				// ignore
			}
		}

		if (srvRecords.length == 0) {
			LOGGER.fine(() -> String.format("No SRV RRs for '%s' found", lookupName));
			return new InetSocketAddress[0];
		}

		final SrvRecord[] srvRrs = srvRecords;
		if (LOGGER.isLoggable(Level.FINER))
			LOGGER.finer(() -> String.format(
					"Found %d SRV RR%s for '%s': %s",
					srvRrs.length, srvRrs.length == 1 ? "" : "s", lookupName, Arrays.toString(srvRrs)));
		else
			LOGGER.fine(() -> String.format(
					"Found %d SRV RR%s for '%s'", srvRrs.length, srvRrs.length == 1 ? "" : "s", lookupName));

		InetSocketAddress[] hostAddresses = sortByRfc2782(srvRecords);

		if (LOGGER.isLoggable(Level.FINER))
			LOGGER.finer(() -> String.format(
					"Selected %d host address%s for '%s': %s",
					hostAddresses.length,
					hostAddresses.length == 1 ? "" : "es",
					lookupName,
					Arrays.toString(hostAddresses)));
		else
			LOGGER.fine(() -> String.format(
					"Selected %d host address%s for '%s'",
					hostAddresses.length, hostAddresses.length == 1 ? "" : "es", lookupName));

		return hostAddresses;
	}
}
