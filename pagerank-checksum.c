#include <stdio.h>
#include <string.h>
#define MAGIC2 0x9e3779b9
#define PRINTREG printf("\n\neax =   0x%08X\nebx =   0x%08X\necx =   0x%08X\nedx =   0x%08X\nesi =   0x%08X\nedi =   0x%08X\ntemp4 = 0x%08X\ntemp8 = 0x%08X\n",eax,ebx,ecx,edx,esi,edi,temp4,temp8);



int main(int argc, char *argv[])
{
	char string[255] = "info:http://";
	int len = 0;
	unsigned int magic = 0xE6359A60;
	int temp4, temp8;

	int i;

	unsigned int eax,ebx,ecx,edx,esi,edi;

	if (argc != 2) {
		printf("Usage: %s <url>\n", argv[0]);
		return 1;
	}

	if (!strncmp(argv[1],"http://",7))
		strncpy(string+5,argv[1],50);
	else {
		strncpy(string+12,argv[1],50);
		if (string[strlen(string)] != '/') strcat(string,"/");
	}

	len = strlen(string);

	esi = magic;
	edi = MAGIC2;
	ebx = edi;
	edx = 0;

	temp4 = len;

	// DIV ECX
	temp8 = len / 12;

	for (i=0;temp8;i+=12,temp8--) {
		edi = ((string[i+7] << 24) + (string[i+6] << 16) + (string[i+5] << 8) + (string[i+4] + edi));
		esi = ((string[i+11] << 24) + (string[i+10] << 16) + (string[i+9] << 8) + (string[i+8] + esi));
		edx = ((string[i+3] << 24) + (string[i+2] << 16) + (string[i+1] << 8) + (string[i]));

		edx = (edx - edi - esi + ebx) ^ (esi >> 0x0D);

		edi = (edi - edx - esi) ^ (edx << 8);

		esi = (esi - edi - edx) ^ (edi >> 0x0D);

		edx = (edx - edi - esi) ^ (esi >> 0x0C);

		edi = (edi - edx - esi) ^ (edx << 16);

		esi = (esi - edi - edx) ^ (edi >> 5);

		edx  = (edx - edi - esi) ^ (esi >> 3);

		edi = (edi - edx - esi) ^ (edx << 0x0A);

		esi = (esi - edi - edx) ^ (edi >> 0x0F);

		temp4 -= 12;

		ebx=edx;
	}


	esi += len;

	//printf("Jumping to case:%d\n",temp4);

	switch (temp4) {

	case 11:
		esi = esi + (string[i+10] << 24);

	case 10:
		esi = esi + (string[i+9] << 16);

	case 9:
		esi = esi + (string[i+8] << 8);

	case 8:
		edi = ((string[i+7] << 24) + (string[i+6] << 16) + (string[i+5] << 8) + (string[i+4] + edi));
		goto Label3;

	case 7:
		edi = edi + (string[i+6] << 16);

	case 6:
		edi = edi + (string[i+5] << 8);

	case 5:
		edi += string[i+4];

	case 4:
	Label3:
		edx = ((string[i+3] << 24) + (string[i+2] << 16) + (string[i+1] << 8) + (string[i] + edx));
		break;
	case 3:
		edx = edx + (string[i+2] << 16);

	case 2:
		edx = edx + (string[i+1] << 8);

	case 1:
		edx = edx + (string[i]);
	case 0:
		break;
	}

	edx = (edx - edi - esi) ^ (esi >> 0x0D);
	edi = (edi - edx - esi) ^ (edx << 8);
	esi = (esi - edi - edx) ^ (edi >> 0x0D);
	edx = (edx - edi - esi) ^ (esi >> 0x0C);
	edi = (edi - edx - esi) ^ (edx << 16);
	esi = (esi - edi - edx) ^ (edi >> 5);
	edx = (edx - edi - esi) ^ (esi >> 3);
	edi = (edi - edx - esi) ^ (edx << 0x0A);
	esi = (esi - edi - edx) ^ (edi >> 0x0F);

	printf("lynx --dump 'http://toolbarqueries.google.com/search?client=navclient-auto&ch=6%u&features=Rank&q=%s'\n",esi,string);
}
