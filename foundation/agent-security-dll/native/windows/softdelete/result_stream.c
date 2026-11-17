/* One append per JSON record. The immutable path belongs to the execution,
 * is inherited by its children and is consumed outside program stdout/stderr. */
static int ensure_dir(const wchar_t *dir);
int prepare_result_stream(void) {
    if(!recovery_config.results[0])return 1;
    wchar_t *parent=heap_wcs_dup(recovery_config.results);
    if(!parent)return 0;
    wchar_t *slash=wcsrchr(parent,L'\\');
    BOOL ok=slash!=NULL;
    if(slash) { *slash=0; ok=ensure_dir(parent); }
    HeapFree(GetProcessHeap(),0,parent);
    if(!ok)return 0;
    HANDLE file=CreateFileW(recovery_config.results,FILE_APPEND_DATA,
        FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)return 0;
    CloseHandle(file); return 1;
}
static void write_result(const GUID *id,LPCWSTR path,LPCWSTR phase,LONG native_status,int disposition,DWORD error) {
    if(!recovery_config.results[0])return;
    WCHAR guid[40]; if(!StringFromGUID2(id,guid,40))return;
    LPCWSTR status=phase?(native_status>=0?L"success":L"failed"):
        disposition>0?L"success":disposition<0?L"unknown":error==ERROR_OPERATION_ABORTED?L"not_executed":L"failed";
    LPCWSTR destination=disposition==1?L"\"recycle_bin\"":disposition==2?L"\"archive\"":
        disposition==3?L"\"broker\"":disposition==4?L"\"permanent\"":disposition==5?L"\"backup\"":disposition<0?L"\"unknown\"":L"null";
    size_t length=path?wcslen(path):0, capacity=6*length+1024;
    WCHAR *record=HeapAlloc(GetProcessHeap(),0,capacity*sizeof(WCHAR));
    if(!record)return;
    int used=swprintf_s(record,capacity,L"{\"kind\":\"%s\",\"operation_ids\":[\"%s\"],\"pid\":%lu,\"status\":\"%s\",\"disposition\":%s,\"os_error\":%lu,\"native_status\":%ld,\"phase\":\"%s\",\"path\":\"",
        phase?L"operation_result":L"result",guid,GetCurrentProcessId(),status,destination,error,native_status,phase?phase:L"");
    if(used<0) { HeapFree(GetProcessHeap(),0,record); return; }
    for(size_t i=0;i<length;++i) {
        WCHAR ch=path[i];
        if(ch==L'"'||ch==L'\\') { record[used++]=L'\\'; record[used++]=ch; }
        else if(ch<32)used+=swprintf_s(record+used,capacity-used,L"\u%04x",ch);
        else record[used++]=ch;
    }
    record[used++]=L'"';record[used++]=L'}';record[used++]=L'\n';record[used]=0;
    int bytes=WideCharToMultiByte(CP_UTF8,0,record,used,NULL,0,NULL,NULL);
    char *utf8=bytes?HeapAlloc(GetProcessHeap(),0,bytes):NULL;
    if(utf8 && WideCharToMultiByte(CP_UTF8,0,record,used,utf8,bytes,NULL,NULL)) {
        DWORD saved=GetLastError(),written; int previous=t_bypass; t_bypass=1;
        HANDLE file=CreateFileW(recovery_config.results,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,
            NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(file!=INVALID_HANDLE_VALUE) { WriteFile(file,utf8,bytes,&written,NULL); CloseHandle(file); }
        t_bypass=previous;SetLastError(saved);
    }
    HeapFree(GetProcessHeap(),0,utf8);HeapFree(GetProcessHeap(),0,record);
}
static void emit_delete_result(const GUID *id,LPCWSTR path,int disposition,DWORD error) {
    if(report_delete)report_delete(id,disposition,error);
    write_result(id,path,NULL,0,disposition,error);
}
static void emit_stage_result(const GUID *id,LPCWSTR path,DWORD stage,LONG status,DWORD error) {
    if(report_stage)report_stage(id,stage,status,error);
    write_result(id,path,stage==1?L"handle_close":stage==2?L"rename":L"replace",status,0,error);
}
