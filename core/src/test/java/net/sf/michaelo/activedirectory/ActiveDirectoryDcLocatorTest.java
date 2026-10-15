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

import javax.naming.ConfigurationException;

import net.sf.michaelo.activedirectory.DcLocatorRequest.Flag;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class ActiveDirectoryDcLocatorTest {

	@Test
	void nullRequest() {
		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();

		assertThrows(NullPointerException.class, () -> locator.locate(null));
	}

	@Test
	void unqualifiedDomainName() {
		DcLocatorRequest request = new DcLocatorRequest();
		request.setDomainName("foo");
		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();

		ConfigurationException e = assertThrows(ConfigurationException.class, () -> locator.locate(request));
		Assertions.assertEquals("domainName must be fully qualified: foo", e.getMessage());

		request.setDomainName("foo.");
		e = assertThrows(ConfigurationException.class, () -> locator.locate(request));
		Assertions.assertEquals("domainName must be fully qualified: foo.", e.getMessage());
	}

	@Test
	void dsIsFlatName() {
		DcLocatorRequest request = new DcLocatorRequest();
		request.addFlag(Flag.DS_IS_FLAT_NAME);
		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();

		ConfigurationException e = assertThrows(ConfigurationException.class, () -> locator.locate(request));
		Assertions.assertEquals("Flag 'DS_IS_FLAT_NAME' is not supported", e.getMessage());
	}

	@Test
	void dsKeyListSupportRequired() {
		DcLocatorRequest request = new DcLocatorRequest();
		request.addFlag(Flag.DS_KEY_LIST_SUPPORT_REQUIRED);
		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();

		ConfigurationException e = assertThrows(ConfigurationException.class, () -> locator.locate(request));
		Assertions.assertEquals(
				"Flag 'DS_KEY_LIST_SUPPORT_REQUIRED' requires flag 'DS_KDC_REQUIRED' to be set", e.getMessage());
	}

	@Test
	void dsTryNextclosestSiteSiteSpecific() {
		DcLocatorRequest request = new DcLocatorRequest();
		request.setSiteName("foo");
		request.addFlag(Flag.DS_TRY_NEXTCLOSEST_SITE);
		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();

		ConfigurationException e = assertThrows(ConfigurationException.class, () -> locator.locate(request));
		Assertions.assertEquals(
				"Flag 'DS_TRY_NEXTCLOSEST_SITE' cannot be combined with site-specific discovery", e.getMessage());
	}

	@Test
	void mutuallyExclusiveFlags() {
		DcLocatorRequest request = new DcLocatorRequest();
		request.addFlag(Flag.DS_GC_SERVER_REQUIRED);
		request.addFlag(Flag.DS_PDC_REQUIRED);
		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();

		ConfigurationException e = assertThrows(ConfigurationException.class, () -> locator.locate(request));
		Assertions.assertEquals("Flags [DS_GC_SERVER_REQUIRED|DS_PDC_REQUIRED] cannot be combined", e.getMessage());

		DcLocatorRequest request2 = new DcLocatorRequest();
		request2.addFlag(Flag.DS_GC_SERVER_REQUIRED);
		request2.addFlag(Flag.DS_KDC_REQUIRED);

		ConfigurationException e2 = assertThrows(ConfigurationException.class, () -> locator.locate(request2));
		Assertions.assertEquals("Flags [DS_GC_SERVER_REQUIRED|DS_KDC_REQUIRED] cannot be combined", e2.getMessage());

		DcLocatorRequest request3 = new DcLocatorRequest();
		request3.addFlag(Flag.DS_KDC_REQUIRED);
		request3.addFlag(Flag.DS_PDC_REQUIRED);

		ConfigurationException e3 = assertThrows(ConfigurationException.class, () -> locator.locate(request3));
		Assertions.assertEquals("Flags [DS_PDC_REQUIRED|DS_KDC_REQUIRED] cannot be combined", e3.getMessage());

		DcLocatorRequest request4 = new DcLocatorRequest();
		request4.addFlag(Flag.DS_KDC_REQUIRED);
		request4.addFlag(Flag.DS_PDC_REQUIRED);
		request4.addFlag(Flag.DS_GC_SERVER_REQUIRED);

		ConfigurationException e4 = assertThrows(ConfigurationException.class, () -> locator.locate(request4));
		Assertions.assertEquals(
				"Flags [DS_GC_SERVER_REQUIRED|DS_PDC_REQUIRED|DS_KDC_REQUIRED] cannot be combined", e4.getMessage());

		DcLocatorRequest request5 = new DcLocatorRequest();
		request5.addFlag(Flag.DS_RETURN_DNS_NAME);
		request5.addFlag(Flag.DS_RETURN_FLAT_NAME);

		ConfigurationException e5 = assertThrows(ConfigurationException.class, () -> locator.locate(request5));
		Assertions.assertEquals("Flags [DS_RETURN_DNS_NAME|DS_RETURN_FLAT_NAME] cannot be combined", e5.getMessage());

		DcLocatorRequest request6 = new DcLocatorRequest();
		request6.addFlag(Flag.DS_IS_DNS_NAME);
		request6.addFlag(Flag.DS_IS_FLAT_NAME);

		ConfigurationException e6 = assertThrows(ConfigurationException.class, () -> locator.locate(request6));
		Assertions.assertEquals("Flags [DS_IS_FLAT_NAME|DS_IS_DNS_NAME] cannot be combined", e6.getMessage());

		DcLocatorRequest request7 = new DcLocatorRequest();
		request7.addFlag(Flag.DS_DIRECTORY_SERVICE_REQUIRED);
		request7.addFlag(Flag.DS_DIRECTORY_SERVICE_6_REQUIRED);

		ConfigurationException e7 = assertThrows(ConfigurationException.class, () -> locator.locate(request7));
		Assertions.assertEquals(
				"Flags [DS_DIRECTORY_SERVICE_REQUIRED|DS_DIRECTORY_SERVICE_6_REQUIRED] cannot be combined",
				e7.getMessage());

		DcLocatorRequest request8 = new DcLocatorRequest();
		request8.addFlag(Flag.DS_DIRECTORY_SERVICE_REQUIRED);
		request8.addFlag(Flag.DS_DIRECTORY_SERVICE_6_REQUIRED);
		request8.addFlag(Flag.DS_DIRECTORY_SERVICE_8_REQUIRED);
		request8.addFlag(Flag.DS_DIRECTORY_SERVICE_9_REQUIRED);
		request8.addFlag(Flag.DS_DIRECTORY_SERVICE_10_REQUIRED);

		ConfigurationException e8 = assertThrows(ConfigurationException.class, () -> locator.locate(request8));
		Assertions.assertEquals(
				"Flags [DS_DIRECTORY_SERVICE_REQUIRED|DS_DIRECTORY_SERVICE_6_REQUIRED|DS_DIRECTORY_SERVICE_8_REQUIRED|DS_DIRECTORY_SERVICE_9_REQUIRED|DS_DIRECTORY_SERVICE_10_REQUIRED] cannot be combined",
				e8.getMessage());
	}

	@Test
	void mutuallyExclusiveConditionalFlags() {
		DcLocatorRequest request = new DcLocatorRequest();
		request.addFlag(Flag.DS_GOOD_TIMESERV_PREFERRED);
		request.addFlag(Flag.DS_GC_SERVER_REQUIRED);
		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();

		ConfigurationException e = assertThrows(ConfigurationException.class, () -> locator.locate(request));
		Assertions.assertEquals(
				"Flags [DS_GC_SERVER_REQUIRED|DS_GOOD_TIMESERV_PREFERRED] cannot be combined", e.getMessage());

		DcLocatorRequest request2 = new DcLocatorRequest();
		request2.addFlag(Flag.DS_GOOD_TIMESERV_PREFERRED);
		request2.addFlag(Flag.DS_KDC_REQUIRED);

		ConfigurationException e2 = assertThrows(ConfigurationException.class, () -> locator.locate(request2));
		Assertions.assertEquals(
				"Flags [DS_KDC_REQUIRED|DS_GOOD_TIMESERV_PREFERRED] cannot be combined", e2.getMessage());

		DcLocatorRequest request3 = new DcLocatorRequest();
		request3.addFlag(Flag.DS_GOOD_TIMESERV_PREFERRED);
		request3.addFlag(Flag.DS_PDC_REQUIRED);

		ConfigurationException e3 = assertThrows(ConfigurationException.class, () -> locator.locate(request3));
		Assertions.assertEquals(
				"Flags [DS_PDC_REQUIRED|DS_GOOD_TIMESERV_PREFERRED] cannot be combined", e3.getMessage());

		DcLocatorRequest request4 = new DcLocatorRequest();
		request4.addFlag(Flag.DS_GOOD_TIMESERV_PREFERRED);
		request4.addFlag(Flag.DS_DIRECTORY_SERVICE_REQUIRED);

		ConfigurationException e4 = assertThrows(ConfigurationException.class, () -> locator.locate(request4));
		Assertions.assertEquals(
				"Flags [DS_DIRECTORY_SERVICE_REQUIRED|DS_GOOD_TIMESERV_PREFERRED] cannot be combined", e4.getMessage());
	}
}
