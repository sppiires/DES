/*Author: Rui Pedro Paiva
Teoria da Informação, LEI, 2008/2009*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <math.h>

unsigned char* encryptDES(unsigned char* inByteArray, long dim, unsigned long long key, int type);
unsigned long long encryptDESplain(unsigned long long plain, unsigned long long* subKeys);
void DESKeySchedule(unsigned long long key, unsigned long long* subKeys);
int DESgeneral (char* inFileName, unsigned long long key, int type);
unsigned char* signature(unsigned char* inByteArray, long dim, unsigned long long key);
int checkSignature(unsigned char* inByteArray, unsigned char* hash);

int DES (char* inFileName, unsigned long long key);
int unDES (char* inFileName, unsigned long long key);


unsigned int rotVi(unsigned int seq, int rot);

unsigned int transformer(unsigned int r, unsigned long long subKey);
void getLc(unsigned long long block, unsigned char *line, unsigned char *column);