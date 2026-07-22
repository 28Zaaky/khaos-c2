/* Inspect raw cookie rows from Edge to detect schema */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static uint16_t be16(const uint8_t *p){return(uint16_t)((p[0]<<8)|p[1]);}
static uint32_t be32(const uint8_t *p){return((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];}
static int sqv(const uint8_t*p,const uint8_t*e,uint64_t*v){uint64_t r=0;int n=0;while(p+n<e&&n<8){uint8_t b=p[n++];r=(r<<7)|(b&0x7f);if(!(b&0x80)){*v=r;return n;}}if(p+n<e)r=(r<<8)|p[n++];*v=r;return n;}
static uint32_t sqsl(uint64_t t){if(!t)return 0;if(t<=4)return(uint32_t)t;if(t==5)return 6;if(t==6||t==7)return 8;if(t==8||t==9)return 0;if(t>=12&&!(t&1))return(uint32_t)((t-12)/2);if(t>=13&&(t&1))return(uint32_t)((t-13)/2);return 0;}
#define NC 32
typedef struct{uint64_t ty[NC];const uint8_t*v[NC];uint32_t l[NC];int n;}Row;
typedef void(*CB)(void*,const Row*);
static void leaf(const uint8_t*db,uint32_t pgsz,uint32_t pgno,int p1,CB cb,void*cx){
    const uint8_t*page=db+(uint64_t)(pgno-1)*pgsz;int h=p1?100:0;
    if(page[h]!=0x0D)return;uint16_t nc=be16(page+h+3);
    const uint8_t*arr=page+h+8,*pe=page+pgsz;
    for(uint16_t i=0;i<nc;i++){
        if(arr+i*2+1>=pe)break;uint16_t off=be16(arr+i*2);
        if(off<(uint16_t)h||off+2>=(uint32_t)pgsz)continue;
        const uint8_t*c=page+off;uint64_t pl=0,ri=0;int n;
        n=sqv(c,pe,&pl);if(n<=0)continue;c+=n;n=sqv(c,pe,&ri);if(n<=0)continue;c+=n;
        const uint8_t*pay=c;if(pay+pl>pe)continue;
        uint64_t hs=0;n=sqv(pay,pay+pl,&hs);if(n<=0||hs>pl)continue;
        const uint8_t*tp=pay+n,*he=pay+hs,*vp=pay+hs;
        Row row;row.n=0;
        while(tp<he&&row.n<NC){uint64_t t=0;n=sqv(tp,he,&t);if(n<=0)break;tp+=n;uint32_t vl=sqsl(t);if(vp+vl>pay+pl)break;row.ty[row.n]=t;row.v[row.n]=vp;row.l[row.n]=vl;row.n++;vp+=vl;}
        if(row.n>0)cb(cx,&row);
    }
}
static void walk(const uint8_t*db,uint32_t pgsz,size_t dbsz,uint32_t pgno,int d,CB cb,void*cx){
    if(d>20)return;uint64_t off=(uint64_t)(pgno-1)*pgsz;if(off+pgsz>dbsz)return;
    const uint8_t*page=db+off;int p1=(pgno==1),h=p1?100:0;
    if(page[h]==0x05){uint16_t nc=be16(page+h+3);uint32_t right=be32(page+h+8);
        const uint8_t*arr=page+h+12;
        for(uint16_t i=0;i<nc;i++){if(arr+i*2+1>=page+pgsz)break;uint16_t co=be16(arr+i*2);
            if(co<(uint16_t)h+4||co>=(uint32_t)pgsz)continue;walk(db,pgsz,dbsz,be32(page+co),d+1,cb,cx);}
        walk(db,pgsz,dbsz,right,d+1,cb,cx);
    }else if(page[h]==0x0D)leaf(db,pgsz,pgno,p1,cb,cx);
}

static uint32_t cookies_rp = 0;
static void fcb(void*cx_,const Row*r){
    (void)cx_;if(cookies_rp||r->n<4)return;
    if(!(r->ty[0]>=13&&(r->ty[0]&1)))return;
    if(r->l[0]!=5||memcmp(r->v[0],"table",5))return;
    if(!(r->ty[1]>=13&&(r->ty[1]&1)))return;
    if(r->l[1]!=7||memcmp(r->v[1],"cookies",7))return;
    uint64_t t=r->ty[3];if(t<1||t>9)return;
    uint32_t rp=0;for(uint32_t i=0;i<r->l[3];i++)rp=(rp<<8)|r->v[3][i];
    cookies_rp=rp;
}

static int hits=0;
static void pcb(void*cx_,const Row*r){
    (void)cx_;if(hits>=8)return;
    printf("Row %d: n=%d\n",++hits,r->n);
    for(int c=0;c<r->n&&c<10;c++){
        uint32_t l=r->l[c];
        printf("  col%d ty=%llu len=%u: ",c,(unsigned long long)r->ty[c],l);
        if(l==0){printf("(empty)");}
        else if(l<=4 && r->ty[c]>=1 && r->ty[c]<=4){
            uint64_t iv=0;for(uint32_t i=0;i<l;i++)iv=(iv<<8)|r->v[c][i];
            printf("INT=%llu",(unsigned long long)iv);
        } else if(l>0&&l<=80&&r->ty[c]>=13&&(r->ty[c]&1)){
            printf("TEXT=%.*s",(int)l,(char*)r->v[c]);
        } else if(l>=3&&(memcmp(r->v[c],"v10",3)==0||memcmp(r->v[c],"v11",3)==0||memcmp(r->v[c],"v20",3)==0)){
            printf("ENC_%.*s (len=%u)",(int)3,(char*)r->v[c],l);
        } else {
            printf("BLOB[%02x%02x%02x%02x...]",r->v[c][0],r->v[c][1],l>2?r->v[c][2]:0,l>3?r->v[c][3]:0);
        }
        printf("\n");
    }
}

int main(void){
    char path[MAX_PATH];
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",path,sizeof(path));
    char tmp[MAX_PATH];GetTempPathA(sizeof(tmp),tmp);
    char tp[MAX_PATH];snprintf(tp,sizeof(tp),"%s~ec.tmp",tmp);
    if(!CopyFileA(path,tp,FALSE)){fprintf(stderr,"copy failed %lu\n",GetLastError());return 1;}
    HANDLE h=CreateFileA(tp,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    LARGE_INTEGER li={0};GetFileSizeEx(h,&li);
    uint8_t*db=(uint8_t*)malloc((size_t)li.QuadPart);
    DWORD rd=0;ReadFile(h,db,(DWORD)li.QuadPart,&rd,NULL);CloseHandle(h);DeleteFileA(tp);
    uint16_t ps=be16(db+16);uint32_t pgsz=(ps==1)?65536u:(uint32_t)ps;
    printf("PageSize=%u  FileSize=%lu\n",pgsz,(unsigned long)rd);
    walk(db,pgsz,rd,1,0,fcb,NULL);
    printf("cookies rootpage=%u\n",cookies_rp);
    if(cookies_rp)walk(db,pgsz,rd,cookies_rp,0,pcb,NULL);
    free(db);return 0;
}
