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

import java.net.InetAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

import net.sf.michaelo.activedirectory.IntFlag;
import net.sf.michaelo.activedirectory.StringUtils;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8401a33f-34a8-40ca-bf03-c3484b66265f"><code>
 * NETLOGON_SAM_LOGON_RESPONSE_EX</code></a> structure.
 */
public class NetlogonSamLogonExResponse extends NetlogonSamLogonBaseResponse {

	private static final Logger LOGGER = Logger.getLogger(NetlogonSamLogonExResponse.class.getName());

	private static final int AF_INET = 2;
	private static final Set<NetlogonNtVersion> NETLOGON_NT_VERSION_5EX =
			Collections.unmodifiableSet(EnumSet.of(NetlogonNtVersion.V1, NetlogonNtVersion.V5EX));

	private Set<DsFlag> flags;
	private UUID domainGuid;
	private String dnsForestName;
	private String dnsDomainName;
	private String dnsHostName;
	private String netbiosDomainName;
	private String netbiosComputerName;
	private String userName;
	private String dcSiteName;
	private String clientSiteName;
	private InetAddress dcSockAddr;
	private String nextClosestSiteName;

	public NetlogonSamLogonExResponse(byte[] netlogonBytes) {
		ByteBuffer buf = wrap(netlogonBytes);

		// Read NETLOGON_SAM_LOGON_RESPONSE_EX structure
		// Opcode
		this.opcode = getOpcode(buf, Opcode.LOGON_SAM_LOGON_RESPONSE_EX);
		// Sbz
		buf.getShort();
		// Flags
		this.flags = IntFlag.fromFlags(DsFlag.class, buf.getInt());
		// DomainGuid
		this.domainGuid = getGuid(buf);
		// DnsForestName
		this.dnsForestName = getCompressedDomainName(buf);
		// DnsDomainName
		this.dnsDomainName = getCompressedDomainName(buf);
		// DnsHostName
		this.dnsHostName = getCompressedDomainName(buf);
		// NetbiosDomainName
		this.netbiosDomainName = getCompressedDomainName(buf);
		// NetbiosComputerName
		this.netbiosComputerName = getCompressedDomainName(buf);
		// UserName
		this.userName = getCompressedDomainName(buf);
		// DcSiteName
		this.dcSiteName = getCompressedDomainName(buf);
		// ClientSiteName
		this.clientSiteName = getCompressedDomainName(buf);
		// NtVersion
		// We need to parse this field ahead of time to know whether the response has DcSockAddr and NextClosestSiteName
		int pos = ((Buffer) buf).position();
		((Buffer) buf).position(buf.limit() - 8);
		this.ntVersion = getNtVersion(buf, NETLOGON_NT_VERSION_5EX);
		((Buffer) buf).position(pos);
		if (this.ntVersion.contains(NetlogonNtVersion.V5EP)) {
			// DcSockAddrSize
			buf.get();
			// DcSockAddr
			// .sin_family
			short sinFamily = buf.getShort();
			if (sinFamily != AF_INET)
				LOGGER.fine(() -> String.format("DcSockAddr.sin_family should be AF_INET (2), but is %d", sinFamily));
			// .sin_port
			buf.getShort();
			// .sin_addr
			byte[] sinAddr = new byte[4];
			buf.get(sinAddr);
			// .sin_zero
			buf.getLong();
			dcSockAddr = getInetAddress(sinAddr);
		}
		// NextClosestSiteName
		if (this.ntVersion.contains(NetlogonNtVersion.VCS)) {
			this.nextClosestSiteName = getCompressedDomainName(buf);
		}
		// Skip already read NtVersion
		buf.getInt();
		// LmNtToken + Lm20Token
		consumeLmTokens(buf);
	}

	public Set<DsFlag> getFlags() {
		return flags;
	}

	public UUID getDomainGuid() {
		return domainGuid;
	}

	public String getDnsForestName() {
		return dnsForestName;
	}

	public String getDnsDomainName() {
		return dnsDomainName;
	}

	public String getDnsHostName() {
		return dnsHostName;
	}

	public String getNetbiosDomainName() {
		return netbiosDomainName;
	}

	public String getNetbiosComputerName() {
		return netbiosComputerName;
	}

	public String getUserName() {
		return userName;
	}

	public String getDcSiteName() {
		return dcSiteName;
	}

	public String getClientSiteName() {
		return clientSiteName;
	}

	public InetAddress getDcSockAddr() {
		return dcSockAddr;
	}

	public String getNextClosestSiteName() {
		return nextClosestSiteName;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("NetlogonSamLogonExResponse[");
		sb.append("opcode: ").append(opcode);
		sb.append(", flags: ").append(IntFlag.toFlagsString(flags));
		sb.append(", domainGuid: ").append(domainGuid);
		sb.append(", dnsForestName: ").append(dnsForestName);
		sb.append(", dnsDomainName: ").append(dnsDomainName);
		sb.append(", dnsHostName: ").append(dnsHostName);
		if (StringUtils.isNotEmpty(netbiosDomainName))
			sb.append(", netbiosDomainName: ").append(netbiosDomainName);
		if (StringUtils.isNotEmpty(netbiosComputerName))
			sb.append(", netbiosComputerName: ").append(netbiosComputerName);
		if (StringUtils.isNotEmpty(userName)) sb.append(", userName: ").append(userName);
		sb.append(", dcSiteName: ").append(dcSiteName);
		if (StringUtils.isNotEmpty(clientSiteName))
			sb.append(", clientSiteName: ").append(clientSiteName);
		if (dcSockAddr != null) sb.append(", dcSockAddr: ").append(dcSockAddr.getHostAddress());
		if (StringUtils.isNotEmpty(nextClosestSiteName))
			sb.append(", nextClosestSiteName: ").append(nextClosestSiteName);
		sb.append(", ntVersion: ").append(IntFlag.toFlagsString(ntVersion));
		sb.append("]");
		return sb.toString();
	}
}
