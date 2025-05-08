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

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Marker interface for enums which represent bitwise integer flags. */
public interface IntFlag {

	int intValue();

	static <T extends Enum<T> & IntFlag> String toFlagsString(Set<T> flags) {
		return flags.stream().map(Enum::name).collect(Collectors.joining("|"));
	}

	static <T extends Enum<T> & IntFlag> int toFlags(Set<T> flags) {
		return flags.stream().map(f -> f.intValue()).reduce(0, (_flags, f) -> _flags | f);
	}

	static <T extends Enum<T> & IntFlag> Set<T> fromFlags(Class<T> enumType, int flags) {
		return Arrays.stream(enumType.getEnumConstants())
				.filter(f -> (flags & f.intValue()) != 0)
				.collect(Collectors.collectingAndThen(
						Collectors.toCollection(() -> EnumSet.noneOf(enumType)), Collections::unmodifiableSet));
	}

	static <T extends Enum<T> & IntFlag> Set<T> fromFlagsString(Class<T> enumType, String flagsStr) {
		return Arrays.stream(flagsStr.split("\\|"))
				.map(str -> Enum.valueOf(enumType, str))
				.collect(Collectors.collectingAndThen(
						Collectors.toCollection(() -> EnumSet.noneOf(enumType)), Collections::unmodifiableSet));
	}

	static <T extends Enum<T> & IntFlag> T fromFlag(Class<T> enumType, int flag) {
		return Arrays.stream(enumType.getEnumConstants())
				.filter(f -> f.intValue() == flag)
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException(String.format("Invalid flag: 0x%08X", flag)));
	}
}
