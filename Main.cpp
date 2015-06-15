#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <SysUtil.h>
#include <CmdUtils.h>
#include <DexFile.h>
#include <DexClass.h>
#include <sha1.h>

static char g_throw_runtimerexception_byte[]= {0x22, 0x00, 0x0b, 0x00, 0x70, 0x10, 0x07, 0x00, 0x00, 0x00, 0x27, 0x00};

static void dexComputeSHA1Digest(const unsigned char* data, size_t length,
    unsigned char digest[])                                       
{   
    SHA1_CTX context;                                             
    SHA1Init(&context);                                           
    SHA1Update(&context, data, length);                           
    SHA1Final(digest, &context);
}   


void dump(unsigned char *src, int len) 
{
   int line = len / 16;
   int last = len - 16 *line;
   for (int j = 0; j < line; j++) {
       for (int i = 0; i < 16; i++)
           printf("%x ", src[i + j*16]);
       printf("\n");
   }
   if (last > 0) {
       for (int i = 0; i < last; i++)
           printf("%x ", src[i + line*16]);
       printf("\n");
   }


}

void process_claas(DexFile *dexFile, const DexClassDef *dexClassDef, FILE *insns_data_fp, char *p)
{
    const u1 *classdata;
    classdata  = dexGetClassData(dexFile, dexClassDef);
    DexClassData tempClassData;
    //u1 **pClassData = &classdata;
    int value ;
    for (int i = 0; i < 4; i++) {
        value = readUnsignedLeb128(&classdata);
        printf("value = %d\n", value);
        ((u4*)&tempClassData)[i] = value;
    }
    DexClassDataHeader *pheader;
    pheader = &tempClassData.header;
    int skipSize;
    skipSize = pheader->staticFieldsSize + pheader->instanceFieldsSize;
    printf("skip: %d\n", skipSize);
    for (int i = 0; i < skipSize *2; i++) {
        value = readUnsignedLeb128(&classdata);
        printf("skip value = %d\n", value);

    }
    int directMethodsSize;
    directMethodsSize = pheader->directMethodsSize;
    int virtualMethodsSize;
    virtualMethodsSize = pheader->virtualMethodsSize;

    printf("directMethodsSize: %d\n", directMethodsSize);
    printf("virtualMethodsSize: %d\n", virtualMethodsSize);

    struct DexMethod *pDexmethod;

    unsigned int codeofffiledoffset;
    unsigned int leb128len;
    if (directMethodsSize > 0) {
        pDexmethod = tempClassData.directMethods = (struct DexMethod *)malloc(directMethodsSize * sizeof(struct DexMethod));
        for (int i = 0; i < directMethodsSize; i++) {
           for (int j =0; j < 3; j++) {
/*
               if (j == 2) {
                   printf("%x, %x, %x\n", p, (char *)classdata, (char *)classdata - p);
                   codeofffiledoffset = (char *)classdata -p;
                   fwrite(&codeofffiledoffset, 1, 4, insns_data_fp);
               }
*/
               value = readUnsignedLeb128(&classdata);
               ((u4*)pDexmethod)[i* 3 + j] = value;
               printf("direct method value: %d\n", value);
/*
               if (j==2) {
                   fwrite(&value, 1, 4, insns_data_fp);
                   leb128len = unsignedLeb128Size(value);
                   classdata -=leb128len;
                   writeUnsignedLeb128((u1 *)classdata, 0x410);
                   classdata += leb128len;
               }
*/

           } 

       }


 
    }

    if (virtualMethodsSize > 0) {
        pDexmethod = tempClassData.virtualMethods = (struct DexMethod*)malloc(virtualMethodsSize * sizeof(struct DexMethod));
        for (int i = 0; i < virtualMethodsSize; i++) {
           for (int j =0; j < 3; j++) {
/*
               if (j == 2) {
                   printf("%x, %x, %x\n", p, (char *)classdata, (char *)classdata - p);
                   codeofffiledoffset = (char *)classdata -p;
                   fwrite(&codeofffiledoffset, 1, 4, insns_data_fp);
               }
*/
               value = readUnsignedLeb128(&classdata);
               ((u4*)pDexmethod)[i*3 + j] = value;
               printf("virtual method value: %d\n", value);
/*
               if (j==2) {
                   fwrite(&value, 1, 4, insns_data_fp);
                   leb128len = unsignedLeb128Size(value);
                   classdata -=leb128len;
                   writeUnsignedLeb128((u1 *)classdata, 0x410);
                   classdata += leb128len;
               }
*/
           } 

       }

    }

    struct DexCode *pDexCode;
    pDexmethod = tempClassData.directMethods;
    for (int i = 0; i < directMethodsSize; i++) {
      //  if (i == 0 || i == 3)
        //    continue;
        printf("%d\n", pDexmethod[i].codeOff);
        pDexCode =  (struct DexCode *)(p + pDexmethod[i].codeOff); 
        if (pDexCode->insnsSize < 6) {
            printf("function inssSize < 6\n");
            continue;
        }


        
       // dump((unsigned char *)pDexCode, 32);
        fwrite(&pDexmethod[i].codeOff, 1, 4, insns_data_fp);
        fwrite(&pDexCode->insnsSize, 1, 4, insns_data_fp);
        dump((unsigned char *)pDexCode, 16 + pDexCode->insnsSize *2);
        fwrite((char *)pDexCode, 1,  16 + pDexCode->insnsSize *2, insns_data_fp);
//fix to throw runtime exception
        if (!pDexCode->registersSize)
            pDexCode->registersSize = 1;
        //pDexCode->insSize = 0;

        if (!pDexCode->outsSize)
            pDexCode->outsSize = 1;
        //pDexCode->triesSize = 0;

        memset(&pDexCode->insns, 0, pDexCode->insnsSize*2);
        memcpy((char *)pDexCode->insns + pDexCode->insnsSize*2 - sizeof(g_throw_runtimerexception_byte), g_throw_runtimerexception_byte, sizeof(g_throw_runtimerexception_byte));

    }

    pDexmethod = tempClassData.virtualMethods;
    for (int i = 0; i < virtualMethodsSize; i++) {
        printf("%d\n", pDexmethod[i].codeOff);
        pDexCode =  (struct DexCode *)(p + pDexmethod[i].codeOff); 
        if (pDexCode->insnsSize < 6) {
            printf("function inssSize < 6\n");
            continue;
        }
        
        fwrite(&pDexmethod[i].codeOff, 1, 4, insns_data_fp);
        fwrite(&pDexCode->insnsSize, 1, 4, insns_data_fp);
        dump((unsigned char *)pDexCode, 16 + pDexCode->insnsSize *2);
        fwrite((char *)pDexCode, 1,  16 + pDexCode->insnsSize *2, insns_data_fp);
//fix to throw runtime exception

        if (!pDexCode->registersSize)
            pDexCode->registersSize = 1;
        //pDexCode->insSize = 0;
        if (!pDexCode->outsSize)
            pDexCode->outsSize = 1;
        //pDexCode->triesSize = 0;

        memset(&pDexCode->insns, 0, pDexCode->insnsSize*2);
        memcpy((char *)pDexCode->insns + pDexCode->insnsSize*2 - sizeof(g_throw_runtimerexception_byte), g_throw_runtimerexception_byte, sizeof(g_throw_runtimerexception_byte));


    }
}


// 替换字符串中特征字符串为指定字符串
int ReplaceStr(char *sSrc, char *sMatchStr, char *sReplaceStr)
{
        int  StringLen;
        char caNewString[1024];

        char *FindPos = strstr(sSrc, sMatchStr);
        if( (!FindPos) || (!sMatchStr) )
                return -1;

        while( FindPos )
        {
                memset(caNewString, 0, sizeof(caNewString));
                StringLen = FindPos - sSrc;
                strncpy(caNewString, sSrc, StringLen);
                strcat(caNewString, sReplaceStr);
                strcat(caNewString, FindPos + strlen(sMatchStr));
                strcpy(sSrc, caNewString);

                FindPos = strstr(sSrc, sMatchStr);
        }

        return 0;
}

#define RESULT_DEX_NAME "classes.dex"

void process_smali(char *dex_name, char *class_name)
{
    char buff[1024];
    char temp_file_name[1024];
    char file_name[1024];

    FILE *src_fp, *temp_fp;
#ifdef _WIN32
    system("rd /s /q out");
#else
    system("rm -rf out");
#endif
    sprintf(buff, "java -jar baksmali.jar %s", dex_name);
    system(buff);

    sprintf(file_name, "out/%s.smali", class_name);
    printf("process smali name: %s\n", class_name);
    sprintf(temp_file_name, "out/%s.smali", "temp");
    printf("product temp file: %s\n", temp_file_name);

#ifdef _WIN32 
    ReplaceStr(file_name, "/", "\\");    
  
    ReplaceStr(temp_file_name, "/", "\\");    
    printf("replace: %s\n", file_name);
    printf("replace: %s\n", temp_file_name);
    
#endif
 
   //insert nop
    
    src_fp = fopen(file_name, "r"); 
    assert(src_fp != NULL); 
    temp_fp = fopen(temp_file_name, "w+");
    assert(temp_fp != NULL);
#define INSERT_NOP_NUM   (6)
#define JAVA_NOP_STRING "    nop\n"
    while (fgets(buff, sizeof(buff), src_fp)) {
         if (strstr(buff, ".end method")) {
             for (int i = 0; i < INSERT_NOP_NUM; i++)
                 fwrite(JAVA_NOP_STRING, 1, strlen(JAVA_NOP_STRING), temp_fp);
         }
         fwrite(buff, 1, strlen(buff), temp_fp);
    }
    
    fflush(NULL);
    fclose(src_fp);
    fclose(temp_fp);
#ifdef _WIN32
    sprintf(buff, "del %s",  file_name);
    system(buff);

    sprintf(buff, "move %s %s", temp_file_name, file_name);
    system(buff);
#else
    sprintf(buff, "rm %s", file_name);
    system(buff);
   
    sprintf(buff, "mv %s %s", temp_file_name, file_name);    
    system(buff);
#endif

    
    sprintf(buff, "java -jar smali.jar out -o %s", dex_name);
    system(buff);
}


int main(int argc, char *argv[])
{
    int size =0;
    if (argc < 3) {
        printf("usage: ./%s zip_file  class_name \n", argv[0]);
        return 1;
    }
// get dex file from zip file

    char temp_dex_name[1024];
    char buff[1024];
    sprintf(temp_dex_name, "%s.temp.dex", argv[1]);
    printf("output dex name is %s\n", temp_dex_name);
    int ret =  dexUnzipToFile(argv[1], temp_dex_name, false);
    printf("ret = %d\n", ret);
    if (ret != 0) {
        printf("did no find file %s\n", argv[1]);
        return -1;
    }


    int class_size = argc - 2;
    for (int i = 0; i < class_size; i++) {
        process_smali(temp_dex_name, argv[i + 2]);
    }
     
    FILE *dex_fp = fopen(temp_dex_name, "rb");
    assert(dex_fp != NULL); 

    FILE *insns_data_fp = fopen("insns_data", "wb+");
    assert(insns_data_fp != NULL);

    ret = fseek(dex_fp, 0, SEEK_END);
    size = ftell(dex_fp);
    printf("size = %d\n", size);
    ret = fseek(dex_fp, 0, SEEK_SET);
    char *p = (char *)malloc(size);
    assert(p != NULL);

    ret = fread(p, 1, size, dex_fp);
    dump((unsigned char *)p, 48);
    assert(ret == size);

    fclose(dex_fp);
   
    printf("befor dexFileParse\n");
    DexFile *dexFile = dexFileParse((const u1 *)p, size, 0); 
    assert(dexFile != NULL);
    printf("affter dexFileParse\n"); 
    FILE *dst_dex_fp = fopen(RESULT_DEX_NAME, "wb+");
    assert(dst_dex_fp != NULL); 
    printf("befor dexCreateClassLookup\n");
    dexFile->pClassLookup = dexCreateClassLookup(dexFile);
    printf("affter dexCreateClassLookup\n");
    char class_def[512];

    for (int i = 0; i < class_size; i++) {
        sprintf(class_def, "L%s;", argv[2 + i]);
        const DexClassDef *dexClassDef = dexFindClass(dexFile, class_def);
        printf("affter dexFindClass\n");
        if (dexClassDef == NULL) {
            printf("did no find class %s\n", class_def);
            goto faild;
        }
        process_claas(dexFile, dexClassDef, insns_data_fp, p);
    }
    unsigned char sha1Digest[kSHA1DigestLen];
    const struct DexHeader *pDexHeader;
    pDexHeader  = dexFile->pHeader;
    dump((unsigned char *)pDexHeader, 32);
    dexComputeSHA1Digest((unsigned char const  *)pDexHeader + 12 + 20, pDexHeader->fileSize -20 - 12, sha1Digest);
    memcpy((char *)pDexHeader + 12, sha1Digest, kSHA1DigestLen); 
     
    ((struct DexHeader *)pDexHeader)->checksum = dexComputeChecksum(pDexHeader);

    fwrite(p, 1, size, dst_dex_fp);
    

    fflush(NULL);
#ifdef _WIN32
    sprintf(buff, "copy %s new_%s", argv[1], argv[1]);
#else
    sprintf(buff, "cp %s new_%s", argv[1], argv[1]);
#endif
    system(buff);

    sprintf(buff, "aapt r new_%s %s", argv[1], RESULT_DEX_NAME); 
    system(buff);
    sprintf(buff, "aapt a new_%s %s", argv[1], RESULT_DEX_NAME);
    system(buff);
    printf("=======process finish: product file new_%s===============\n", argv[1]);
faild:
    fclose(insns_data_fp);
    fclose(dst_dex_fp);  
    dexFileFree(dexFile); 
    free(p);
    remove(temp_dex_name);
    
    return 0;
}
