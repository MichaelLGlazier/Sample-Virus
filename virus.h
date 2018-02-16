#ifndef VIRUS_H_
#define VIRUS_H_

/*
*
*Asserts:
*	fp is not valid.
*
*/
int findSentinal(char* host);

int copyHost(int hostOffset, char* host, char** argv);

int isInfectable(char* arg);
int isExecutable(char* arg1, char* arg2);
int mutate(int fd, char* arg, int offset);
int isInfected(char* arg);
int copyProgram(char* arg, int virus);
#endif