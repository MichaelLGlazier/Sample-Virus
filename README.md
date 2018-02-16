# Sample-Virus
This is a simple virus that only spreads itself and is contained by several safe measures such as programs that it is going to
infect can not have the execute bit set. The virus works by infecting a host, which can be done with the command 'Make host'. 
The host will take a program or filename as a command line argument and infect that program, while running the host program.
The virus process requires read access to the file it is overwriting, and write access to the directory it is in and to the 
temp folder. The virus needs these because it will first copy its own binary (with some modifications) to a temporary file, and 
then the target's binary is appended to that file. The virus finalizes the process by replacing the original file with the
infected copy.
The virus also mutates so performing a checksum of the same two identical host files infected by two different instances of the
virus will produce a different hash.
This virus is made purely for educational purposes, and should not be used maliciously. The virus has built in restrictions to 
prevent it from spreading on a system without the user specifically allowing it to spread.
