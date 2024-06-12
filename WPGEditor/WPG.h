#include <Windows.h>
#include <iostream>
#include "Cryptor.h"
#include <zlib.h>
#include <string>

// defines the unique fourcc code used to identify the file format
#define FOURCC 0x474B5052
// defines the max length of a package name
#define MAX_PACK_NAME 0x80

// defines the pack actions
// no action
#define ACTION_NONE 0
// compresses the files in the package
#define ACTION_COMPRESS 1
// encrypts the files in the package
#define ACTION_ENCRYPT 2

namespace WPG
{
	// definition of the structure of a package file header
	typedef struct _PACKAGE_HEADER
	{
		// the package fourcc code
		DWORD FourCC;
		// the package version
		DWORD Version;
		// contains the package root name	
		CHAR PackageRoot[MAX_PACK_NAME];
		// contains the number of sections within the package
		DWORD NumberOfSections;
	} PACKAGE_HEADER, *PPACKAGE_HEADER;

	// definition of the structure of a package file section
	typedef struct _PACKAGE_SECTION
	{
		// the name of the file accociated with the section
		CHAR FileName[MAX_PACK_NAME];
		// the offset of the data block from the base of the file
		DWORD DataOffset;
		// the size of the data block
		DWORD DataSize;
		// contains information on whether the data is encrypted or compressed
		DWORD DataInfo;
	} PACKAGE_SECTION, *PPACKAGE_SECTION;

	// stores the cryptor seed
	const BYTE pSeed[] = { 0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89 };

	// stores the cryptor block
	const BYTE pBlock[] = { 0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81, 0x6F, 0xBA, 0xD9, 0xFA, 0x36, 0x16, 0x25, 0x01 };

	// unpacks the specified package
	BOOL Unpack(LPCSTR lpPath);

	// packs the specified directory into a package
	BOOL Pack(LPCSTR lpPath, LPCSTR lpRoot, DWORD dwAction);

	// unpacks all of the wpg files within the given directory
	BOOL UnpackDir(LPCSTR lpPath);
}