 /*

  			        
		-------------------------------------------------------
                 TAPION POLYMORPHIC DECRYPTOR GENERATOR
         -------------------------------------------------------
			     by Piotr Bania <bania.piotr@gmail.com>
				      http://pb.specialised.info

					     All rights reserved!


  */


#define	  ENGINE_VERSION	"ver. 0.1c"
#define   RELEASE_DATE		"16/09/2005"

#include "t_poly.h"


int main(int argc, char *argv[])
{
	setup_random();
	mutate_regs();

	garbage_global_flag = -1;


	printf("--------------------------------------------------------------------\n");
	printf("TAPiON2 (%s) Polymorphic Decryptor Generator\n",ENGINE_VERSION);
	printf("by Piotr Bania <bania.piotr@gmail.com>\n");
	printf("http://pb.specialised.info\n");
	printf("--------------------------------------------------------------------\n\n");



	if (argc < 4)
	{
		printf("[*] Usage: tapion2.exe <shellcode_file> <garbage_size> <do_jumps>\n");
		printf("[*] Where: <shellcode_file> - is a file with shellcode to crypt\n");
		printf("[*] Where: <garbage_size> - is a garbage size (from 0-5)\n");
		printf("[*] When:  <garbage_size> = 'R', garbage size is randomized\n");
		printf("[*] When:  <garbage_size> > 5, no garbage is stored\n");
		printf("[*] Where: <do_jumps> - 0/1 to generate garbage with jumps\n");
		getch();
		return 0;
	}

	if (strcmp(argv[2],"R") == 0)
	{
		garbage_global_flag = 0;
		printf("[+] Garbage step is randomized!\n");
	}

	if ((atoi(argv[2]) > 0) && (atoi(argv[2]) < 6))
	{
		garbage_global_flag = atoi(argv[2]);
		printf("[+] Garbage step = %d\n",atoi(argv[2]));
	}


	if (garbage_global_flag == -1)
		printf("[+] No garbage layers will be inserted\n");


	if (atoi(argv[3]) == 0)
		printf("[+] Not using jump garbaging\n");

	if (atoi(argv[3]) == 1)
		printf("[+] Using jump garbaging\n");

	if ((atoi(argv[3]) != 1) && (atoi(argv[3]) != 0))
	{
		printf("[-] Invalid <do_jumps> option\n");
		getch();
		return 0;
	}


	do_jumps = atoi(argv[3]);


	strncpy(filename,argv[1],MAX_PATH);

	sample();

	getch();

	return 0;
}
