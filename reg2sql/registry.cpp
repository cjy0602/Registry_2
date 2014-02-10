#ifndef __PARSER_H_
#define __PARSER_H_
#include "parser.h"
#endif

int parser(int argc, char** argv, REGQUEUE *q) {
    char path[0x1000]={0}, *data; FILE* f; int size;  
    //REGQUEUE q;

    if(argc<2||!(f=fopen(argv[1],"rb"))) return printf("hive path err");
    
    fseek(f,0,SEEK_END); 
    if(!(size=ftell(f))) return printf("empty file");
    
    rewind(f); data=(char*)malloc(size); 
    fread(data,size,1,f); 
    fclose(f);

    // we just skip 1k header and start walking root key tree
    walk(path, (key_block*)(data+0x1020), q);
    free(data);
	/* while (!q.empty())
    {
        printf ("%s : %u\n" , q.front()->key, q.front()->time );
        q.pop();
    }
	*/
    return 0;
}
