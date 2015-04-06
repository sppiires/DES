/*Author: Rui Pedro Paiva
Teoria da Informação, LEI, 2008/2009*/

#include "DES.h"

unsigned long function(unsigned long right, unsigned long long subKey);
unsigned int c_shift(unsigned int block, int n);


//função para encriptação
int DES (char* inFileName, unsigned long long key)
{
	return DESgeneral(inFileName, key, 0);
}


//função para decriptação
int unDES (char* inFileName, unsigned long long key)
{
	return DESgeneral(inFileName, key, 1);
}


//função geral para encriptação (type = 0) e decriptação (type = 1) de um ficheiro 
int DESgeneral (char* inFileName, unsigned long long key, int type)
{
	FILE* DESInFile;
	unsigned char* inByteArray;
	long inFileSize;
	unsigned char* crpByteArray;
	char* outFileName;
	int write;
	char response;
	struct stat stFileInfo;
	FILE* DESOutFile;
	char suf[5];


	//abrir ficheiro e ler tamanho
	DESInFile = fopen(inFileName, "rb");
	if (DESInFile == NULL)
	{
		printf("Error opening file for reading. Exiting...\n");
		return 1;
	}
	fseek(DESInFile, 0L, SEEK_END);
	inFileSize = ftell(DESInFile);  //ignore EOF
	fseek(DESInFile, 0L, SEEK_SET);


	//ler ficheiro inteiro para array inByteArray	
	inByteArray = (unsigned char*) calloc(inFileSize, sizeof(unsigned char)); 
	fread(inByteArray, 1, inFileSize, DESInFile);


	//criar assinatura
	if (type == 0)  //encripta‹o
	{
		/******* ADICIONAR CîDIGO: 
		 implementar ˆ fun‹o:
		 unsigned char* signature(unsigned char* inByteArray, long dim, unsigned long long key)  // ver abaixo
		 e adicionar hash aos dados
		 ***********************/
	}
	
	
	//encriptar dados e assinatura no array
	crpByteArray = encryptDES(inByteArray, inFileSize, key, type);
		
	//flush do crpByteArray para ficheiro
	//nome do ficheiro de saída
	if (type == 0)  //encriptação
	{
		outFileName = (char*) calloc(strlen(inFileName) + 5, sizeof(char)); 
		strcpy(outFileName, inFileName);
		strcat(outFileName, ".DES");
	}
	else  //decriptação
	{
		strcpy(suf, &inFileName[strlen(inFileName) - 4]);
		if (strcmp(suf, ".DES") == 0)
		{		
			outFileName = (char*) calloc(strlen(inFileName) + 5, sizeof(char)); 
			strcpy(outFileName, "DES_");
			strcat(outFileName, inFileName);
			outFileName[strlen(outFileName) - 4] = 0;
		}
		else
		{
			outFileName = (char*) calloc(14, sizeof(char));
			strcpy(outFileName, "DES_decrypted");
		}

	}
	
	
	//verificar assinatura
	if (type == 1)
	{
		/******* ADICIONAR CîDIGO: 
		 implementar ˆ fun‹o:
		 int checkSignature(unsigned char* inByteArray, unsigned char* hash)  // ver abaixo
		 e retirar hash aos dados
		 abortar desencripta‹o caso a verifica‹o da assinatura n‹o passe no teste
		 ***********************/		
	}
	
	//criar ficheiro
	write = 1;
	if(stat(outFileName, &stFileInfo) == 0) //see if file already exists
	{
		printf ("File already exists. Overwrite (y/n)?: ");
		response = getchar();
		if (response == 'n')
			write = 0;
		printf("\n");
		fflush(stdin);
	}

	if (write)
	{
		DESOutFile = fopen(outFileName, "wb");
		if (DESOutFile == NULL)
		{
			printf("Error opening file for writing!!! Exiting...\n");
			return -1;
		}
		fwrite(crpByteArray, 1, inFileSize, DESOutFile);
		fclose(DESOutFile);
	}
	
	//finalizações
	free(inByteArray);
	free(outFileName);
	free(crpByteArray);
	fclose(DESInFile);

	return 0;	
}


// função para encriptação/decriptação de dados no array inByteArray, de dimensão dim
unsigned char* encryptDES(unsigned char* inByteArray, long dim, unsigned long long key, int type)
{
	unsigned long long subKeys[16], tempKeys[16];
	unsigned char* outByteArray;
	unsigned long long plain, cipher, aux1, aux2;
	int i, j;
    
    
    
	
	//obtém sub-keys (16 de comprimento 48)
	/**** ADICIONAR CÓDIGO PARA A FUNÇÃO DESKEYSCHEDULE (ABAIXO) ********/
	DESKeySchedule(key, subKeys);
 

	if (type == 1) //decrypt --> inverter subKeys
	{
		/**************** ADICIONAR CÓDIGO ****************************/
		j=0;
		for (i=15; i>=0; i--){
			tempKeys[j] = subKeys[i];
			j++;
		}
		
		for (i=0; i<16; i++)
			subKeys[i] = tempKeys[i];
        
        
       
	}

	outByteArray = (unsigned char*) calloc(dim, sizeof(unsigned char)); 
	i = 0;
	plain = 0;
	while (i < dim)
	{
		plain = 0;
		j = i;
		while (j < i + 8 && j < dim)
		{
 			plain = plain | ((unsigned long long)inByteArray[j] << (64 - 8*(j-i+1)));
			j++;
		}

		//determina cifra
		if (j - i == 8)  //ficheiro é múltiplo de 8 bytes
			/**** ADICIONAR CÓDIGO PARA A FUNÇÃO ENCRYPTDESPLAIN (ABAIXO) ********/
			cipher = encryptDESplain(plain, subKeys);
		else
			cipher = plain;


		//guarda cifra no array de saída
		j = i;
		while (j < i + 8 && j < dim)
		{
			outByteArray[j] = (unsigned char) (cipher >> (56 - 8*(j-i)) & (0xFF));
			j++;
		}

		i = j;		
	}

	return outByteArray;
}


/************************************************************************************/
/***************************** ADICIONAR CóDIGO *************************************/
/************************************************************************************/


// função para encriptação de uma mensagem de 64 bits (plain), com base nas subKeys
//devolve a mensagem cifrada
unsigned long long encryptDESplain(unsigned long long plain, unsigned long long* subKeys)
{
    int ip[] = {58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7};
    
    int ipinv[] = {40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6 ,46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9,  49, 17, 57, 25};
    
    int i;
    unsigned long long temp_plain;
    unsigned long long permutation_1 = 0;
    unsigned long long permutation_2 = 0;
    unsigned int l;
    unsigned int r;
    unsigned int oldR;
    unsigned long long temp_swap;
    unsigned long long swap;
    
    //printf("plainText: %#llx\n", plain);
    
    
    for(i = 0; i < 64; i++)	//Percorre a matriz IP
    {
        //Obtém o bit de IP1 em key
        temp_plain = 0;
        temp_plain = (plain << (ip[i] - 1));
        temp_plain = (temp_plain >> (63));
        //Coloca o bit em C
        permutation_1 = (permutation_1 << 1);
        permutation_1 = (permutation_1 | temp_plain);
    }
    
    l = (permutation_1 >> 32);
    permutation_1 = (permutation_1 << 32);
    r = (permutation_1 >> 32);
    //printf("L0: %x\n", l);
    //printf("R0: %x\n", r);
    
    for(i = 0; i < 16; i++)
    {
        oldR = r;
        r = l ^ transformer(r, subKeys[i]);
        l = oldR;
    }
    
    //printf("R16: %#x, L16: %#x", r, l);
    
    swap = r;
    swap = (swap << 32) | l;
    
    for(i = 0; i < 64; i++)	//Percorre a matriz IP^-1
    {
        //Obtém o bit de IP^-1 em key
        temp_swap = 0;
        temp_swap = (swap << (ipinv[i] - 1));
        temp_swap = (temp_swap >> (63));
        //Coloca o bit em C
        permutation_2 = (permutation_2 << 1);
        permutation_2 = (permutation_2 | temp_swap);
    }
    
    //printf("cifra(C): %#llx", permutation_2);
    return permutation_2;
}

unsigned int transformer(unsigned int r, unsigned long long subKey)
{
    int e[] = {32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1};
    
    int p[] = {16, 7,  20, 21,
        29, 12, 28, 17,
        1,  15, 23, 26,
        5,  18, 31, 10,
        2,  8,  24, 14,
        32, 27, 3,  9,
        19, 13, 30, 6,
        22, 11, 4,  25};
    
    int s1[4][16] = {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};
    
    int s2[4][16] = {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
			  	  {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
			  	  {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
			  	  {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};
    
    int s3[4][16] = {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
			  	  {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
			  	  {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
			  	  {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};
    
    int s4[4][16] = {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
			  	  {3,15,0,6,10,1,13,8,9,4,2,11,12,7,2,14}};
    
    int s5[4][16] = {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};
    
    int s6[4][16] = {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};
    
    int s7[4][16] = {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};
    
    int s8[4][16] = {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
    
    int i;
    unsigned int temp_r;
    unsigned long long expansion = 0;
    unsigned long long block;
    unsigned char line;
    unsigned char column;
    unsigned int subs = 0;
    unsigned int temp_subs;
    unsigned int permutation = 0;
    
    
    for(i = 0; i < 48; i++)
    {
        //Obtém o bit de IP1 em key
        temp_r = 0;
        temp_r = (r << (e[i] - 1));
        temp_r = (temp_r >> (31));
        //Coloca o bit em C
        expansion = (expansion << 1);
        expansion = (expansion | temp_r);
    }
    
    //printf("T: %#llx", expansion);
    
    expansion = expansion ^ subKey;
    
    //printf("T': %#llx", expansion);
    
    block = (expansion & 0xFC0000000000);
    block = (block >> (6 * 7));
    getLc(block, &line, &column);
    subs = (subs | s1[line][column]);
    
    
    block = (expansion & 0x3F000000000);
    block = (block >> (6 * 6));
    getLc(block, &line, &column);
    subs = (subs << 4);
    subs = (subs | s2[line][column]);
    
    block = (expansion & 0xFC0000000);
    block = (block >> (6 * 5));
    getLc(block, &line, &column);
    subs = (subs << 4);
    subs = (subs | s3[line][column]);
    
    block = (expansion & 0x3F000000);
    block = (block >> (6 * 4));
    getLc(block, &line, &column);
    subs = (subs << 4);
    subs = (subs | s4[line][column]);
    
    block = (expansion & 0xFC0000);
    block = (block >> (6 * 3));
    getLc(block, &line, &column);
    subs = (subs << 4);
    subs = (subs | s5[line][column]);
    
    block = (expansion & 0x3F000);
    block = (block >> (6 * 2));
    getLc(block, &line, &column);
    subs = (subs << 4);
    subs = (subs | s6[line][column]);
    
    block = (expansion & 0xFC0);
    block = (block >> (6 * 1));
    getLc(block, &line, &column);
    subs = (subs << 4);
    subs = (subs | s7[line][column]);
    
    block = (expansion & 0x3F);
    block = (block >> (6 * 0));
    getLc(block, &line, &column);
    subs = (subs << 4);
    subs = (subs | s8[line][column]);
    
    //printf("T'': %#llx", subs);
    
    for(i = 0; i < 32; i++)	//Percorre a matriz P
    {
        //Obtém o bit de P em key
        temp_subs = 0;
        temp_subs = (subs << (p[i] - 1));
        temp_subs = (temp_subs >> (31));
        //Coloca o bit em C
        permutation = (permutation << 1);
        permutation = (permutation | temp_subs);			
    }
    //printf("T''': %#llx", permutation);
    return permutation;
}


void getLc(unsigned long long block, unsigned char *line, unsigned char *column)
{
    *column = (block & 0x1E);
    *column = (*column >> 1);
    
    *line = (block & 0x20);
    *line = 2 * (*line >> 5);
    *line = *line + (block & 0x1);
}

// função para gerar sub-keys (uma chave para cada uma das 16 iterações)
void DESKeySchedule(unsigned long long key, unsigned long long* subKeys)
{
	int pc1[] = {57, 49, 41, 33, 25, 17, 9, 
				1, 58, 50, 42, 34, 26, 18, 
				10, 2, 59, 51, 43, 35, 27, 
				19, 11, 3, 60, 52, 44, 36, 
				63, 55, 47, 39, 31, 23, 15, 
				7, 62, 54, 46, 38, 30, 22, 
				14, 6, 61, 53, 45, 37, 29, 
				21, 13, 5, 28, 20, 12, 4};

	int pc2[] = {14, 17, 11, 24, 1, 5,
				3, 28, 15, 6, 21, 10,
				23, 19, 12, 4, 26, 8,
				16, 7, 27, 20, 13, 2,
				41, 52, 31, 37, 47, 55,
				30, 40, 51, 45, 33, 48,
				44, 49, 39, 56, 34, 53,
				46, 42, 50, 36, 29, 32};
	
	int circular_shift[17] = {0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};	/* indice 0 nao utilizado */

	int i, j;
	unsigned long long temp_key, CD[16];
	unsigned long long perm_1 = 0, perm_2;
	unsigned int C[17];
	unsigned int D[17];
	
	// Permutacao inicial (PC-1)
	for (i=0; i<56; i++){
	
		// Obter bit de key
		temp_key = 0;
		temp_key = (key << (pc1[i]-1));
		temp_key = (temp_key >> 63);
		
		// Colocar o bit na permutacao (56 bits)
		perm_1 = (perm_1 << 1);
		perm_1 = (perm_1 | temp_key);
	}
	
	// Dividir permutacao em dois blocos de 28 bits (C[0] e D[0])
	C[0] = (perm_1 >> 28);		/* C[0] fica com os 28 bits da esquerda */
	perm_1 = (perm_1 << 36);	/* 28 + 8 primeiros bits a 0 */
	D[0] = (perm_1 >> 36);		/* D[0] fica com os 28 bits da direita */
	
    
    printf("C[0]: %#llx\n", C[0]);
    printf("D[0]: %#llx\n", D[0]);
	// Criar 16 blocos C e D atraves da tabela circular shift
	for (i=1; i<=16; i++){
		C[i] = c_shift(C[i-1], circular_shift[i]);
		D[i] = c_shift(D[i-1], circular_shift[i]);
	}
	
	// Formar as subkeys atraves de permutacoes dos blocos usando a PC-2
	for (i=0; i<16; i++){
		perm_2 = 0;
		
		// Juntar C[i] e D[i] para obter CD[i]
		CD[i] = C[i+1];
		CD[i] = (CD[i] << 28);
		CD[i] = (CD[i] | D[i+1]);
		
		// fazer permutacao (PC-2)
		for (j=0; j<48; j++){
			// Obter bit
			temp_key = 0;
			temp_key = (CD[i] << (8+pc2[j]-1));
			temp_key = (temp_key >> 63);
			
			// Colocar bit na subKeys[i]
			perm_2 = (perm_2 << 1);
			perm_2 = (perm_2 | temp_key);
		}
		
		subKeys[i] = perm_2;
	}
}

// Funcao que faz o circular shift de n posicoes no bloco recebido
unsigned int c_shift(unsigned int block, int n){
	int i;
	unsigned int out = block;
	unsigned int bit;
	
	for (i=0; i<n; i++){
		bit = (out <<4);	/* bit mais significativo do bloco */
		bit = (bit>>31);
		out = (out << 5);		/* tirar bit mais significativo */
		out = (out >> 4);		/* tirar zeros a mais no fim */
		out = (out | bit);		/* atualizar bit menos significativo do bloco */
	}
	
	return out;
}

/*
// fun‹o para cria‹o de de uma hash a partir dos dados do ficheiro, usando MDC-4
unsigned char* signature(unsigned char* inByteArray, long dim, unsigned long long key)


//fun‹o para verifica‹o da assinatura: verificar se a hash criada a partir dos dados Ž igual ˆ hash recebida
int checkSignature(unsigned char* inByteArray, unsigned char* hash)
*/
