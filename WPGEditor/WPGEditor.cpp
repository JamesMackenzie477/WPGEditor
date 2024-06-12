#include "WPGEditor.h"

// the main entry of the program
int main(int argc, char *argv[])
{
	// validates the arguments
	if (argc > 2)
	{
		// checks the arguments
		if (_stricmp(argv[1], "/d") == 0)
		{
			// notifies user
			std::cout << "[+] Unpacking: " << argv[2] << std::endl;
			// unpacks the specified package
			if (WPG::UnpackDir(argv[2]))
			{
				// notifies user
				std::cout << "[+] Successfully unpacked: " << argv[2] << std::endl;
			}
			else
			{
				// notifies user
				std::cout << "[-] Unpacking failed " << GetLastError() << std::endl;
			}
		}
		else if (_stricmp(argv[1], "/u") == 0)
		{
			// notifies user
			std::cout << "[+] Unpacking: " << argv[2] << std::endl;
			// unpacks the specified package
			if (WPG::Unpack(argv[2]))
			{
				// notifies user
				std::cout << "[+] Successfully unpacked: " << argv[2] << std::endl;
			}
			else
			{
				// notifies user
				std::cout << "[-] Unpacking failed " << GetLastError() << std::endl;
			}
		}
		else if (_stricmp(argv[1], "/p") == 0)
		{
			// unpacks the specified directory
			if (WPG::Pack(argv[2], argv[3], (DWORD)(*(char*)argv[4] - '0')))
			{
				// notifies user
				std::cout << "[+] Successfully packed: " << argv[2] << std::endl;
			}
			else
			{
				// notifies user
				std::cout << "[-] Packing failed " << GetLastError() << std::endl;
			}
		}
	}
	else
	{
		// notifies user
		std::cout << "[-] Invalid arguments" << std::endl;
	}
	// exits program
	return 0;
}