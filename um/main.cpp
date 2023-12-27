#include "driver.hpp"
#include <iostream>

int main()
{
	printf("Setup: %d\n", driver::setup());
	
	cmd_t cmd{};
	cmd.verification_code = SYSCALL_CODE;

	//cmd.operation = memory_read;
	//printf("Read sent: %d\n", driver::send_cmd(&cmd));

	//cmd.operation = memory_write;
	//printf("Write sent: %d\n", driver::send_cmd(&cmd));

	//cmd.operation = module_base;
	//printf("Module base sent: %d\n", driver::send_cmd(&cmd));
	stepx:
	cmd.target_pid = driver::get_process_id("RustClient.exe");
	cmd.operation = mget_cr3;
	driver::send_cmd(&cmd);
	
	getchar();
	LPCWSTR ModuleToSearch;
	ModuleToSearch = L"RustClient.exe";

	cmd.ModuleName = ModuleToSearch;
	cmd.operation = module_base;
	driver::send_cmd(&cmd);
	std::cout << "RustClient :" << cmd.ModuleBase << std::endl;
	getchar();
	/*while (driver::get_process_id("RustClient.exe") > 0)
	{
	}
	if (driver::get_process_id("RustClient.exe") == NULL)
	{
		printf("Waiting Rust..\n");
		Sleep(1);
		goto stepx;
	}*/
	getchar();

	return 0;
}
//[utils::get_process_cr3] Invalid CR3 Detected  000000036E07F000 
//[utils::get_process_cr3] Fixed CR3 #2(Main) :  0000001B7822B000 
//[utils::get_process_cr3] Fixed CR3  #1(Main) : 000001CA013C2000 
