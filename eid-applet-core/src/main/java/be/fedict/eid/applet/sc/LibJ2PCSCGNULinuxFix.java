/*
 * eID Applet Project.
 * Copyright (C) 2015 e-Contract.be BVBA.
 * Copyright (C) 2008-2013 FedICT.
 * 
 * Takes from Commons eID project.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

/*
 * author Frank Marien
 */

package be.fedict.eid.applet.sc;

import java.io.File;

/**
 * Encapsulate fixes regarding the dynamic loading of the pcsclite library on
 * GNU/Linux Systems. statically call LibJ2PCSCGNULinuxFix.fixNativeLibrary()
 * before using a TerminalFactory.
 * 
 * @author Frank Cornelis
 * @author Frank Marien
 */
public final class LibJ2PCSCGNULinuxFix {
	private static final int PCSC_LIBRARY_VERSION = 1;
	private static final String SMARTCARDIO_LIBRARY_PROPERTY = "sun.security.smartcardio.library";
	private static final String LIBRARY_PATH_PROPERTY = "java.library.path";
	private static final String GNULINUX_OS_PROPERTY_PREFIX = "Linux";
	private static final String PCSC_LIBRARY_NAME = "pcsclite";
	private static final String UBUNTU_MULTILIB_32_SUFFIX = "i386-linux-gnu";
	private static final String UBUNTU_MULTILIB_64_SUFFIX = "x86_64-linux-gnu";
	private static final String JRE_BITNESS_PROPERTY = "os.arch";
	private static final String OS_NAME_PROPERTY = "os.name";
	private static final String JRE_BITNESS_32_VALUE = "i386";
	private static final String JRE_BITNESS_64_VALUE = "amd64";

	private static enum UbuntuBitness {
		NA, PURE32, PURE64, MULTILIB
	};

	private LibJ2PCSCGNULinuxFix() {
		super();
	}

	/**
	 * Make sure libpcsclite is found. The libj2pcsc.so from the JRE attempts to
	 * dlopen using the linker name "libpcsclite.so" instead of the appropriate
	 * "libpcsclite.so.1". This causes libpcsclite not to be found on GNU/Linux
	 * distributions that don't have the libpcsclite.so symbolic link. This
	 * method finds the library and forces the JRE to use it instead of
	 * attempting to locate it by itself. See also:
	 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529339
	 * 
	 * Does nothing if not on a GNU/Linux system
	 */
	public static void fixNativeLibrary(final Logger logger) {
		final String osName = System.getProperty(OS_NAME_PROPERTY);
		if ((osName != null)
				&& (osName.startsWith(GNULINUX_OS_PROPERTY_PREFIX))) {
			logger.debug("OS is [" + osName + "]. Enabling PCSC library fix.");
			final File libPcscLite = findGNULinuxNativeLibrary(
					PCSC_LIBRARY_NAME, PCSC_LIBRARY_VERSION, logger);
			if (libPcscLite != null) {
				logger.debug("Setting [" + SMARTCARDIO_LIBRARY_PROPERTY
						+ "] to [" + libPcscLite.getAbsolutePath() + "]");
				System.setProperty(SMARTCARDIO_LIBRARY_PROPERTY,
						libPcscLite.getAbsolutePath());
			}
		} else {
			logger.debug("OS is [" + osName
					+ "]. Not Enabling PCSC library fix.");
		}
	}

	// ----------------------------------------------------------------------------------------
	// -------------------------------- supporting private methods.
	// ---------------------------
	// ----------------------------------------------------------------------------------------

	/*
	 * Determine Ubuntu-type multilib configuration
	 */
	private static UbuntuBitness getUbuntuBitness() {
		File multilibdir = new File("/lib/" + UBUNTU_MULTILIB_32_SUFFIX);
		boolean has32 = multilibdir.exists() && multilibdir.isDirectory();
		multilibdir = new File("/lib/" + UBUNTU_MULTILIB_64_SUFFIX);
		boolean has64 = multilibdir.exists() && multilibdir.isDirectory();

		if (has32 && (!has64)) {
			return UbuntuBitness.PURE32;
		} else if ((!has32) && has64) {
			return UbuntuBitness.PURE64;
		} else if (has32 && has64) {
			return UbuntuBitness.MULTILIB;
		} else {
			return UbuntuBitness.NA;
		}
	}

	/*
	 * return the path with extension appended, if it wasn't already contained
	 * in the path
	 */
	private static String extendLibraryPath(final String libPath,
			final String extension) {
		if (libPath.contains(extension)) {
			return libPath;
		}
		return libPath + ":" + extension;
	}
	private static String addMultiarchPath(final String libPath,
			final String suffix) {
		String retval = extendLibraryPath(libPath, "/lib/" + suffix);
		return extendLibraryPath(retval, "/usr/lib/" + suffix);
	}

	/*
	 * Oracle Java 7, java.library.path is severely limited as compared to the
	 * OpenJDK default and doesn't contain Ubuntu 12's MULTILIB directories.
	 * Test for Ubuntu in various configs and add the required paths
	 */
	private static String fixPathForUbuntuMultiLib(final String libraryPath,
			final Logger logger) {
		logger.debug("Looking for Debian/Ubuntu-style multilib installation.");

		switch (getUbuntuBitness()) {
		case PURE32:
			// pure 32-bit Ubuntu. Add the 32-bit lib dir.
			logger.debug("pure 32-bit Debian/Ubuntu detected, adding library paths containing 32-bit multilib suffix: "
					+ UBUNTU_MULTILIB_32_SUFFIX);
			return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_32_SUFFIX);

		case PURE64:
			// pure 64-bit Ubuntu. Add the 64-bit lib dir.
			logger.debug("pure 64-bit Debian/Ubuntu detected, adding library paths containing 64-bit multilib suffix: "
					+ UBUNTU_MULTILIB_64_SUFFIX);
			return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_64_SUFFIX);

		case MULTILIB: {
			// multilib Ubuntu. Let the currently running JRE's bitness
			// determine which lib dir to add.
			logger.debug("Multilib Ubuntu detected. Using JRE Bitness.");

			final String jvmBinaryArch = System
					.getProperty(JRE_BITNESS_PROPERTY);
			if (jvmBinaryArch == null) {
				return libraryPath;
			}

			logger.debug("JRE Bitness is [" + jvmBinaryArch + "]");

			if (jvmBinaryArch.equals(JRE_BITNESS_32_VALUE)) {
				logger.debug("32-bit JRE, using 32-bit multilib suffix: "
						+ UBUNTU_MULTILIB_32_SUFFIX);
				return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_32_SUFFIX);
			}

			if (jvmBinaryArch.equals(JRE_BITNESS_64_VALUE)) {
				logger.debug("64-bit JRE, using 64-bit multilib suffix: "
						+ UBUNTU_MULTILIB_64_SUFFIX);
				return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_64_SUFFIX);
			}
		}
			break;

		default: {
			logger.debug("Did not find Debian/Ubuntu-style multilib.");
		}
		}
		return libraryPath;
	}

	/*
	 * Finds .so.version file on GNU/Linux. avoid guessing all GNU/Linux
	 * distros' library path configurations on 32 and 64-bit when working around
	 * the buggy libj2pcsc.so implementation based on JRE implementations adding
	 * the native library paths to the end of java.library.path. Fixes the path
	 * for Oracle JRE which doesn't contain the Ubuntu MULTILIB directories
	 */
	private static File findGNULinuxNativeLibrary(final String baseName,
			final int version, final Logger logger) {
		// get java.library.path
		String nativeLibraryPaths = System.getProperty(LIBRARY_PATH_PROPERTY);
		if (nativeLibraryPaths == null) {
			return null;
		}

		logger.debug("Original Path=[" + nativeLibraryPaths + "]");

		// when on Ubuntu, add appropriate MULTILIB path
		nativeLibraryPaths = fixPathForUbuntuMultiLib(nativeLibraryPaths,
				logger);

		logger.debug("Path after Ubuntu multilib Fixes=[" + nativeLibraryPaths
				+ "]");

		// scan the directories in the path and return the first library called
		// "baseName" with version "version"

		final String libFileName = System.mapLibraryName(baseName) + "."
				+ version;

		logger.debug("Scanning path for [" + libFileName + "]");

		for (String nativeLibraryPath : nativeLibraryPaths.split(":")) {
			logger.debug("Scanning [" + nativeLibraryPath + "]");
			final File libraryFile = new File(nativeLibraryPath, libFileName);
			if (libraryFile.exists()) {
				logger.debug("[" + libFileName + "] found in ["
						+ nativeLibraryPath + "]");
				return libraryFile;
			}
		}

		logger.debug("[" + libFileName + "] not found.");
		return null;
	}
}
