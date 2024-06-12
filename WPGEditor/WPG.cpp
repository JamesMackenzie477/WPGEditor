#include "WPG.h"

namespace File
{
	// creates the given path
	VOID CreatePath(LPCSTR lpPath)
	{
		// converts the char array to a standard string
		std::string Path(lpPath);
		// stores the current path
		std::string CurrentPath;
		// loops to create each directory
		while (TRUE)
		{
			// finds the directory seperator
			size_t index = Path.find("\\");
			// validates the result
			if (index == std::string::npos)
				// interated thorugh all directories so we are done
				break;
			// adds the directory to the current path
			CurrentPath += Path.substr(0, index + 1);
			// increments the positing of path to the next directory
			Path.erase(Path.begin(), Path.begin() + index + 1);
			// creates the directory
			CreateDirectory(CurrentPath.c_str(), NULL);
		}
	}

	// reads the specified file into a buffer
	PVOID ReadW(LPCWSTR lpFile, PDWORD dwOut)
	{
		// opens the requested file
		HANDLE hFile = CreateFileW(lpFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		// validates the handle
		if (hFile != INVALID_HANDLE_VALUE)
		{
			// gets the file size
			DWORD dwSize = GetFileSize(hFile, NULL);
			// validates the file size
			if (dwSize != INVALID_FILE_SIZE)
			{
				// creates a buffer for the file
				PVOID pFile = malloc(dwSize);
				// validates the buffer
				if (pFile)
				{
					// stores the number of bytes read
					DWORD dwBytes;
					// reads the file into the buffer
					if (ReadFile(hFile, pFile, dwSize, &dwBytes, NULL) && dwBytes == dwSize)
					{
						// closes the file handle
						CloseHandle(hFile);
						// sets the output size
						*dwOut = dwSize;
						// funtion succeeded
						return pFile;
					}
					// frees the buffer
					VirtualFree(pFile, 0, MEM_RELEASE);
				}
			}
			// closes the file handle
			CloseHandle(hFile);
		}
		// function failed
		return FALSE;
	}

	// reads the specified file into a buffer
	PVOID ReadA(LPCSTR lpFile, PDWORD dwOut)
	{
		// opens the requested file
		HANDLE hFile = CreateFileA(lpFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		// validates the handle
		if (hFile != INVALID_HANDLE_VALUE)
		{
			// gets the file size
			DWORD dwSize = GetFileSize(hFile, NULL);
			// validates the file size
			if (dwSize != INVALID_FILE_SIZE)
			{
				// creates a buffer for the file
				PVOID pFile = malloc(dwSize);
				// validates the buffer
				if (pFile)
				{
					// stores the number of bytes read
					DWORD dwBytes;
					// reads the file into the buffer
					if (ReadFile(hFile, pFile, dwSize, &dwBytes, NULL) && dwBytes == dwSize)
					{
						// closes the file handle
						CloseHandle(hFile);
						// sets the output size
						*dwOut = dwSize;
						// funtion succeeded
						return pFile;
					}
					// frees the buffer
					VirtualFree(pFile, 0, MEM_RELEASE);
				}
			}
			// closes the file handle
			CloseHandle(hFile);
		}
		// function failed
		return FALSE;
	}

	// write the specified buffer and length to the disk
	BOOL WriteA(LPCSTR lpFile, PVOID pBuffer, DWORD dwSize)
	{
		// creates the path
		CreatePath(lpFile);
		// creates the requested file
		HANDLE hFile = CreateFileA(lpFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		// validates the handle
		if (hFile != INVALID_HANDLE_VALUE)
		{
			// stores the n umber of bytes written
			DWORD dwBytes;
			// writes the data to the file
			if (WriteFile(hFile, pBuffer, dwSize, &dwBytes, NULL) && dwBytes == dwSize)
			{
				// closes the file handle
				CloseHandle(hFile);
				// function succeeded
				return TRUE;
			}
		}
		// function failed
		return FALSE;
	}

	// write the specified buffer and length to the disk
	BOOL WriteW(LPCWSTR lpFile, PVOID pBuffer, DWORD dwSize)
	{
		// creates the requested file
		HANDLE hFile = CreateFileW(lpFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		// validates the handle
		if (hFile != INVALID_HANDLE_VALUE)
		{
			// stores the n umber of bytes written
			DWORD dwBytes;
			// writes the data to the file
			if (WriteFile(hFile, pBuffer, dwSize, &dwBytes, NULL) && dwBytes == dwSize)
			{
				// closes the file handle
				CloseHandle(hFile);
				// function succeeded
				return TRUE;
			}
		}
		// function failed
		return FALSE;
	}
}

namespace WPG
{
	// validates the specified package
	BOOL Validate(PVOID pPackage, DWORD dwSize)
	{
		// casts the pointer to a package header
		PPACKAGE_HEADER pHeader = (PPACKAGE_HEADER)pPackage;
		// validates the fourcc code and the package version
		if (pHeader->FourCC == FOURCC && pHeader->Version <= 1)
		{
			// used to calculate the file size
			DWORD dwFileSize = sizeof(PACKAGE_HEADER) + (sizeof(PACKAGE_SECTION) * pHeader->NumberOfSections);
			// gets the package sections array
			PPACKAGE_SECTION pSections = (PPACKAGE_SECTION)pHeader + 1;
			// iterates through the package sections
			for (int i = 0; i < pHeader->NumberOfSections; i++)
			{
				// validates the section attributes
				if (!pSections[i].FileName || dwFileSize != pSections[i].DataOffset || pSections[i].DataSize > 0x6400000 || pSections[i].DataInfo & 0xFFFFFFFC)
				{
					// file is not valid
					return FALSE;
				}
				// calculates the file size
				dwFileSize += pSections[i].DataSize;
			}
			// checks the file size
			if (dwFileSize == dwSize)
			{
				// file is valid
				return TRUE;
			}
		}
		// file is not valid
		return FALSE;
	}

	// decrypts the given data buffer
	BOOL Decrypt(PVOID pData, DWORD dwSize, PVOID* pBuffer, PDWORD dwOut)
	{
		// validates the arguments
		if (pData && dwSize && dwOut)
		{
			// gets the decrypted data size
			DWORD dwDecrypted = *(PDWORD)pData + 16;
			// gets the encrypted data size
			DWORD dwEncrypted = dwSize - 4;
			// validates the size
			if (dwDecrypted - 17 <= 0x63FFFFF)
			{
				// gets the encrypted data address
				pData = (PDWORD)pData + 1;
				// creates a buffer for the decrypted data
				if (PVOID pDecrypted = malloc(dwDecrypted))
				{
					// initalizes the cryptor
					Cryptor pCryptor = Cryptor((PDWORD)pSeed, (PDWORD)pBlock);
					// decrypts the data
					if (pCryptor.Decrypt((PDWORD)pData, dwEncrypted, (PDWORD)pDecrypted))
					{
						// sets the output size
						*dwOut = dwDecrypted;
						// sets the new buffer
						*pBuffer = pDecrypted;
						// function succeeded
						return TRUE;
					}
				}
			}
		}
		// function failed
		return FALSE;
	}

	PVOID Encrypt(PVOID pData, DWORD dwSize, PDWORD dwOut)
	{
		// constructs a buffer
		PVOID pEncrypted = malloc(dwSize + 4);
		// writes the old size
		*(PDWORD)pEncrypted = dwSize;
		// a pointer to the data
		PVOID pEncData = (PBYTE)pEncrypted + 4;
		// initalizes the cryptor
		Cryptor pCryptor = Cryptor((PDWORD)pSeed, (PDWORD)pBlock);
		// encrypts the data
		if (pCryptor.Encrypt((PDWORD)pData, dwSize, (PDWORD)pEncData))
		{
			// sets the output size
			*dwOut = dwSize + 4;
			// returns the buffer
			return pEncrypted;
		}
		// function failed
		return NULL;
	}

	// decompresses the given data buffer
	BOOL Decompress(PVOID pData, DWORD dwSize, PVOID* pBuffer, PDWORD dwOut)
	{
		// validates the arguments
		if (pData && dwSize && dwOut)
		{
			// gets the decompressed data size
			DWORD dwDecompressed = *(PDWORD)pData;
			// gets the compressed data size
			DWORD dwCompressed = dwSize - 4;
			// validates the size
			if (dwDecompressed - 1 <= 0x63FFFFF)
			{
				// gets the compressed data address
				pData = (PDWORD)pData + 1;
				// creates a buffer for the decompressed data
				if (PVOID pDecompressed = malloc(dwDecompressed))
				{
					// decompresses the data
					if (uncompress((PBYTE)pDecompressed, &dwDecompressed, (PBYTE)pData, dwCompressed) == Z_OK)
					{
						// sets the output size
						*dwOut = dwDecompressed;
						// sets the buffer address
						*pBuffer = pDecompressed;
						// function succeeded
						return TRUE;
					}
				}
			}
		}
		// function failed
		return FALSE;
	}

	// compresses the given data buffer
	PVOID Compress(PVOID pData, DWORD dwSize, PDWORD dwOut)
	{
		// gets the compressed data size
		if (DWORD dwCompressed = compressBound(dwSize))
		{
			// constructs a buffer
			PVOID pCompressed = malloc(dwCompressed + 4);
			// writes the old size
			*(PDWORD)pCompressed = dwSize;
			// a pointer to the data
			PVOID pCompData = (PBYTE)pCompressed + 4;
			// compresses the data
			if (compress((PBYTE)pCompData, &dwCompressed, (PBYTE)pData, dwSize) == Z_OK)
			{
				// sets the output size
				*dwOut = dwCompressed + 4;
				// returns the buffer
				return pCompressed;
			}
		}
		// function failed
		return NULL;
	}

	// unpacks the specified package
	BOOL Unpack(LPCSTR lpPath)
	{
		// stores the package size
		DWORD dwSize;
		// reads the package into a buffer
		if (PVOID pPackage = File::ReadA(lpPath, &dwSize))
		{
			// validates the file is a package
			if (Validate(pPackage, dwSize))
			{
				// casts the buffer to a package header
				PPACKAGE_HEADER pHeader = (PPACKAGE_HEADER)pPackage;
				// gets the package sections array
				PPACKAGE_SECTION pSections = (PPACKAGE_SECTION)(pHeader + 1);
				// iterates through the sections
				for (int i = 0; i < pHeader->NumberOfSections; i++)
				{
					// notifies user
					std::cout << "[+] Unpacking: " << pSections[i].FileName << std::endl;
					// gets the data address
					PVOID pData = (PBYTE)pPackage + pSections[i].DataOffset;
					// gets the data size
					DWORD dwData = pSections[i].DataSize;
					// checks if the data is encrypted
					if (pSections[i].DataInfo & 2)
					{
						// notifies user
						std::cout << "[+] Decrypting: " << pSections[i].FileName << std::endl;
						// decrypts the given file
						if (!Decrypt(pData, dwData, &pData, &dwData))
						{
							// notifies user
							std::cout << "[-] There was a problem decrypting: " << pSections[i].FileName << " " << GetLastError() << std::endl;
							// frees the buffer
							free(pData);
							// failed
							goto FAIL_FREE;
						}
						// notifies user
						std::cout << "[+] Successfully decrypted: " << pSections[i].FileName << std::endl;
					}
					// checks if the data is compressed
					if (pSections[i].DataInfo & 1)
					{
						// notifies user
						std::cout << "[+] Decompressing: " << pSections[i].FileName << std::endl;
						// decompresses the data
						if (!Decompress(pData, dwData, &pData, &dwData))
						{
							// notifies user
							std::cout << "[-] There was a problem decompressing: " << pSections[i].FileName << " " << GetLastError() << std::endl;
							// frees the buffer
							free(pData);
							// failed
							goto FAIL_FREE;
						}
						// notifies user
						std::cout << "[+] Successfully decompressed: " << pSections[i].FileName << std::endl;
					}
					// writes the package to the disk
					if (!File::WriteA(pSections[i].FileName, pData, dwData))
					{
						// notifies user
						std::cout << "[-] There was a problem unpacking: " << pSections[i].FileName << " " << GetLastError() << std::endl;
						// failed
						goto FAIL_FREE;
					}
					// notifies user
					std::cout << "[+] Successfully unpacked: " << pSections[i].FileName << std::endl;
				}
				// clears the buffer
				free(pPackage);
				// function succeeded
				return TRUE;
			}
FAIL_FREE:
			// clears the buffer
			free(pPackage);
		}
		// function failed
		return FALSE;
	}

	// calculates the package buffer size and amount of files
	BOOL GetPackageSize(LPCSTR lpPath, DWORD dwAction, PDWORD dwSize, PDWORD dwFiles)
	{
		// creates the string
		std::string Path(lpPath);
		// adds the dir tag to the string
		Path += "\\*";
		// stores the file information
		WIN32_FIND_DATA FileInfo;
		// gets the first file in the directory
		HANDLE hFind = FindFirstFileA(Path.c_str(), &FileInfo);
		// validates the handle
		if (hFind != INVALID_HANDLE_VALUE)
		{

			// iterates through the directory files
			do
			{
				// casts the file name to a standard string
				std::string File(FileInfo.cFileName);
				// constructs the full path
				std::string FullPath(std::string(lpPath) + std::string("\\") + File);
				// gets the extension index
				size_t ExtensionIndex = File.find(".");
				// if the file is a file
				if (ExtensionIndex != std::string::npos)
				{
					// filter directory dots
					// opens the file
					HANDLE hFile = CreateFileA(FullPath.c_str(), NULL, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					// validates the handle
					if (hFile != INVALID_HANDLE_VALUE)
					{
						// gets the file size
						*dwSize += GetFileSize(hFile, NULL);
						// gets the file count
						*dwFiles += 1;
						// closes the handle
						CloseHandle(hFile);
					}
				}
				else
				{
					// recursively call this function
					GetPackageSize(FullPath.c_str(), dwAction, dwSize, dwFiles);
				}
				// if the file is a wpg file then extract it
				// if the file is a directory then recursively call this function
			} while (FindNextFile(hFind, &FileInfo) != 0);
		}
		// returns the calculated size
		return TRUE;
	}

	// constructs the sections in a given package buffer for the given directory
	VOID ConstructSections(LPCSTR lpPath, LPCSTR lpRoot, PVOID pPackage, DWORD dwDataOffset, DWORD dwAction, PDWORD dwOut)
	{
		// gets the package header
		PPACKAGE_HEADER pHeader = (PPACKAGE_HEADER)pPackage;
		// creates the string
		std::string Path(lpPath);
		// adds the dir tag to the string
		Path += "\\*";
		// stores the file information
		WIN32_FIND_DATA FileInfo;
		// gets the first file in the directory
		HANDLE hFind = FindFirstFileA(Path.c_str(), &FileInfo);
		// validates the handle
		if (hFind != INVALID_HANDLE_VALUE)
		{
			// iterates through the directory files
			do
			{
				// casts the file name to a standard string
				std::string File(FileInfo.cFileName);
				// constructs the full path
				std::string FullPath(std::string(lpPath) + std::string("\\") + File);
				// gets the root path
				std::string RootPath(std::string(lpRoot) + std::string("\\") + File);
				// gets the extension index
				size_t ExtensionIndex = File.find(".");
				// if the file is a file
				if (ExtensionIndex != std::string::npos)
				{
					// gets the file size
					DWORD dwSize;
					// reads the file
					if (PVOID pFile = File::ReadA(FullPath.c_str(), &dwSize))
					{
						// if the file is to be encrypted
						// gets the section header
						PPACKAGE_SECTION pSection = (PPACKAGE_SECTION)((PBYTE)pPackage + sizeof(PACKAGE_HEADER) + (sizeof(PACKAGE_SECTION) * pHeader->NumberOfSections));
						// adds the file path name
						memcpy(&pSection->FileName, RootPath.c_str(), RootPath.length());
						// sets the data info
						pSection->DataInfo = dwAction;
						// checks the section count
						if (pHeader->NumberOfSections == 0)
						{
							// calculates the data poisition
							pSection->DataOffset = sizeof(PACKAGE_HEADER) + (sizeof(PACKAGE_SECTION) * dwDataOffset);
						}
						else
						{
							// gets the previous section
							PPACKAGE_SECTION pPrevSection = (PPACKAGE_SECTION)pPackage + pHeader->NumberOfSections;
							// calculates the data poisition
							pSection->DataOffset = pPrevSection->DataOffset + pPrevSection->DataSize;
						}
						// if the file is to be compressed
						if (dwAction & ACTION_COMPRESS)
						{
							// compresses the data
							pFile = Compress(pFile, dwSize, &dwSize);
						}
						if (dwAction & ACTION_ENCRYPT)
						{
							// encrypts the data
							pFile = Encrypt(pFile, dwSize, &dwSize);
						}

						// sets the data size
						pSection->DataSize = dwSize;
						// writes the data to the package
						memcpy((PBYTE)pPackage + pSection->DataOffset, pFile, dwSize);
						// frees the file buffer
						free(pFile);
						// increments the package size
						*dwOut += pSection->DataSize;
						// increments the number of sections
						pHeader->NumberOfSections += 1;
					}
				}
				else
				{
					// recursively call this function
					ConstructSections(FullPath.c_str(), RootPath.c_str(), pPackage, dwDataOffset, dwAction, dwOut);
				}
				// if the file is a wpg file then extract it
				// if the file is a directory then recursively call this function
			} while (FindNextFile(hFind, &FileInfo) != 0);
		}
	}

	// packs the specified directory into a package
	BOOL Pack(LPCSTR lpPath, LPCSTR lpRoot, DWORD dwAction)
	{
		// constructs the data path
		std::string Root(lpRoot);

		std::string DataPath(lpPath);

		// gets the first directory
		size_t Position = Root.find("\\");

		// validates position
		if (Position != std::string::npos)
		{
			DataPath = std::string(lpPath) + Root.substr(Root.find("\\"), Root.length());
		}

		// stores the package sections
		DWORD dwSections = NULL;
		// stores the overall size
		DWORD dwPackageSize = NULL;
		// calculates the resulting package size
		if (GetPackageSize(DataPath.c_str(), dwAction, &dwPackageSize, &dwSections) && dwSections > 0)
		{
			// creates a buffer for the package
			PVOID pPackage = malloc(sizeof(PACKAGE_HEADER) + (sizeof(PACKAGE_SECTION) * dwSections) + dwPackageSize);
			// constructs the package header
			PPACKAGE_HEADER pHeader = (PPACKAGE_HEADER)pPackage;
			// sets the fourcc code
			pHeader->FourCC = FOURCC;
			// sets the package version
			pHeader->Version = 1;
			// sets the package root name
			memcpy(&pHeader->PackageRoot, Root.c_str(), Root.length());
			// sets the number of sections
			pHeader->NumberOfSections = 0;
			// stores the data size
			DWORD dwSize = sizeof(PACKAGE_HEADER) + (sizeof(PACKAGE_SECTION) * dwSections);
			// constructs the package
			ConstructSections(DataPath.c_str(), Root.substr(0, Root.length() - 1).c_str(), pPackage, dwSections, dwAction, &dwSize);
			// writes the pacakge to the disk
			if (File::WriteA((std::string(lpPath) + ".wpg").c_str(), pPackage, dwSize))
			{
				// function succeeded
				return TRUE;
			}
			// gets the folder name to name the package root
			// iterates through every directory file
			// performs action and writes data to a buffer
			// calculates the overall size of the file
			// creates the file buffer
			// write header
			// write sections
			// write data
			// write package to disk
		}
		// function failed
		return FALSE;
	}

	BOOL UnpackDir(LPCSTR lpPath)
	{
		// creates the string
		std::string Path(lpPath);
		// adds the dir tag to the string
		Path += "\\*";
		// stores the file information
		WIN32_FIND_DATA FileInfo;
		// gets the first file in the directory
		HANDLE hFind = FindFirstFileA(Path.c_str(), &FileInfo);
		// validates the handle
		if (hFind != INVALID_HANDLE_VALUE)
		{
			// iterates through the directory files
			do
			{
				// casts the file name to a standard string
				std::string File(FileInfo.cFileName);
				// constructs the full path
				std::string FullPath(std::string(lpPath) + std::string("\\") + File);
				// gets the extension index
				size_t ExtensionIndex = File.find(".");
				// if the file is a file
				if (ExtensionIndex != std::string::npos)
				{
					// gets the file extension
					std::string Extension = File.substr(ExtensionIndex, File.length());
					// checks the file extension
					if (Extension.compare(".wpg") == 0)
					{
						// unpacks the package
						if (!Unpack(FullPath.c_str()))
						{
							// function failed
							return FALSE;
						}
					}
				}
				else
				{
					// recursively calls this function
					if (!UnpackDir(FullPath.c_str()))
					{
						// function failed
						return FALSE;
					}
				}
				// if the file is a wpg file then extract it
				// if the file is a directory then recursively call this function
			} while (FindNextFile(hFind, &FileInfo) != 0);
			// function succeeded
			return TRUE;
		}
		// function failed
		return FALSE;
	}
}