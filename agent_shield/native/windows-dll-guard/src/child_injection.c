#include "child_pe.c"

static int inject_import_child(HANDLE process){
 void *pbi[6]={0};void *image=NULL;BYTE header[4096];SIZE_T got;
 if(query_process(process,0,pbi,sizeof(pbi),NULL)!=0){SetLastError(ERROR_PARTIAL_COPY);return 0;}
 if(!ReadProcessMemory(process,(BYTE*)pbi[1]+0x10,&image,sizeof(image),&got))return 0;
 if(!ReadProcessMemory(process,image,header,sizeof(header),&got))return 0;
 const IMAGE_NT_HEADERS64 *nt=child_pe_header(header);
 if(!nt)return 0;
 DWORD old_rva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
 IMAGE_IMPORT_DESCRIPTOR old[128];unsigned count=0;
 if(old_rva){
  for(;count<128;count++){
   if(!ReadProcessMemory(process,(BYTE*)image+old_rva+count*sizeof(old[0]),&old[count],sizeof(old[0]),&got))return 0;
   IMAGE_IMPORT_DESCRIPTOR empty={0};
   if(!memcmp(&old[count],&empty,sizeof(empty)))break;
  }
 }
 char name[CHILD_IMPORT_PATH_CAPACITY];BOOL substituted=FALSE;UINT page=GetACP();
 int len=WideCharToMultiByte(page,page==CP_UTF8?WC_ERR_INVALID_CHARS:WC_NO_BEST_FIT_CHARS,
     self_path,-1,name,sizeof(name),NULL,page==CP_UTF8?NULL:&substituted);if(!len)return 0;
 if(substituted){SetLastError(ERROR_NO_UNICODE_TRANSLATION);return 0;}
 DWORD limit_error=child_import_limits(count,(unsigned)len);
 if(limit_error){SetLastError(limit_error);return 0;}
 BYTE *remote=NULL;ULONG_PTR start=((ULONG_PTR)image+nt->OptionalHeader.SizeOfImage+65535)&~(ULONG_PTR)65535;
 for(unsigned delta=0;delta<64u*1024u*1024u;delta+=65536){
  remote=(BYTE*)VirtualAllocEx(process,(void*)(start+delta),8192,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(remote)break;
 }
 if(!remote)return 0;
 ULONG_PTR distance=remote-(BYTE*)image;if(!distance||distance>=0xFFFFFFFFu){SetLastError(ERROR_INVALID_ADDRESS);return 0;}DWORD rva=(DWORD)distance;
 BYTE payload[8192]={0};
 CopyMemory(payload+4096,&config,sizeof(config));
 unsigned no=((count+2)*sizeof(IMAGE_IMPORT_DESCRIPTOR)+7)&~7u;
 unsigned ilt=(no+len+7)&~7u,iat=ilt+16,bn=iat+16;if(bn+32>4096){SetLastError(ERROR_INSUFFICIENT_BUFFER);return 0;}
 IMAGE_IMPORT_DESCRIPTOR *desc=(IMAGE_IMPORT_DESCRIPTOR*)payload;
 unsigned insertion=0;HMODULE soft=GetModuleHandleW(L"jiuwen_softdelete.dll");
 if(soft && count){
  char loaded[1200],imported[1200]={0};
  DWORD n=GetModuleFileNameA(soft,loaded,sizeof(loaded));
  if(!n||n>=sizeof(loaded))return 0;
  for(unsigned i=0;i<sizeof(imported);i++){
   if(!ReadProcessMemory(process,(BYTE*)image+old[0].Name+i,imported+i,1,&got)||got!=1)return 0;
   if(!imported[i])break;
   if(i==sizeof(imported)-1){SetLastError(ERROR_INSUFFICIENT_BUFFER);return 0;}
  }
  if(!_stricmp(imported,loaded))insertion=1;
 }
 for(unsigned i=0;i<count;i++)desc[i+(i>=insertion)]=old[i];
 desc[insertion].OriginalFirstThunk=rva+ilt;desc[insertion].Name=rva+no;desc[insertion].FirstThunk=rva+iat;
 CopyMemory(payload+no,name,len);
 *(ULONGLONG*)(payload+ilt)=rva+bn;*(ULONGLONG*)(payload+iat)=rva+bn;CopyMemory(payload+bn+2,"GuardMarker",12);
 if(!WriteProcessMemory(process,remote,payload,sizeof(payload),&got))return 0;
 DWORD previous,tmp;if(!VirtualProtectEx(process,image,sizeof(header),PAGE_READWRITE,&previous))return 0;
 IMAGE_DATA_DIRECTORY entry={rva,(count+2)*sizeof(*desc)},zero={0};
 ULONG_PTR off=(BYTE*)&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]-header;
 int ok=WriteProcessMemory(process,(BYTE*)image+off,&entry,sizeof(entry),&got);
 off=(BYTE*)&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]-header;
 ok=ok&&WriteProcessMemory(process,(BYTE*)image+off,&zero,sizeof(zero),&got);
 DWORD error=ok?ERROR_SUCCESS:GetLastError();
 if(!VirtualProtectEx(process,image,sizeof(header),previous,&tmp))return 0;
 if(!ok)SetLastError(error);
 return ok;
}



