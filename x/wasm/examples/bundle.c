// Copyright 2026 The Outline Authors. SPDX-License-Identifier: Apache-2.0
// Freestanding reactor: all mutable application state belongs to the session
// supplied by the host. No heap, WASI, sockets, mutable singleton or active config.
typedef unsigned int u32;
typedef unsigned char u8;
#ifndef VARIANT
#define VARIANT 1
#endif
#define EXPORT __attribute__((visibility("default")))
#define COUNT 256
#define MAX 65536
typedef struct { u32 generation, kind, child, key, phase, written; u32 relay_len; u8 relay[256]; } Object;
typedef struct { Object objects[COUNT]; } Session;
static const char catalog[] = "stream.identity\nstream.xor\nstream.split\npacket.identity\npacket.xor\n";
static int eq(const u8 *p, u32 n, const char *s) { u32 i=0; for (; s[i]; i++) if (i>=n || p[i]!=(u8)s[i]) return 0; return i==n; }
static Object *get(Session *s, u32 h) { u32 i=(h&65535); if (!i || i>COUNT) return 0; Object *o=&s->objects[i-1]; return o->kind && o->generation==(h>>16) ? o : 0; }
static u32 alloc(Session *s) { for (u32 i=0;i<COUNT;i++) { Object *o=&s->objects[i]; if (!o->kind && o->generation<65535) { o->generation++; return (o->generation<<16)|(i+1); } } return 0; }
EXPORT u32 abi_version(void) { return 1; }
EXPORT u32 catalog_ptr(void) { return (u32)catalog; }
EXPORT u32 catalog_len(void) { return sizeof(catalog)-1; }
EXPORT u32 session_size(void) { return sizeof(Session); }
// Host supplies fresh zeroed memory. Only object allocation metadata needs init;
// clearing every relay byte in the interpreter adds needless startup work.
EXPORT u32 session_init(Session *s) { for(u32 i=0;i<COUNT;i++) {s->objects[i].kind=0;s->objects[i].generation=0;} return 1; }
EXPORT u32 describe(u8 *name, u32 n) { if (eq(name,n,"stream.identity") || eq(name,n,"stream.xor") || eq(name,n,"stream.split")) return 1; if(eq(name,n,"packet.identity") || eq(name,n,"packet.xor")) return 2; return 0; }
EXPORT u32 object_create(Session *s,u8 *name,u32 n,u32 key,u8 *relay,u32 rn) {
    u32 kind=0;
    if(eq(name,n,"stream.identity")) kind=1;
    if(eq(name,n,"stream.xor")) kind=2;
    if(eq(name,n,"stream.split")) kind=3;
    if(eq(name,n,"packet.identity")) kind=4;
    if(eq(name,n,"packet.xor")) kind=5;
    if(!kind || rn>255 || (kind==3 ? (!key || key>65535) : key>255)) return 0;
    u32 h=alloc(s); if(!h) return 0;
    Object *o=&s->objects[(h&65535)-1]; o->kind=kind; o->child=0; o->key=key; o->phase=0; o->written=0; o->relay_len=rn;
    for(u32 i=0;i<rn;i++) o->relay[i]=relay[i];
    return h;
}
EXPORT u32 object_open(Session *s,u32 factory) {
    Object *f=get(s,factory); if(!f || f->child) return 0;
    u32 h=alloc(s); if(!h) return 0; Object *o=&s->objects[(h&65535)-1];
    o->kind=f->kind; o->child=1; o->key=f->key; o->phase=0; o->written=0; o->relay_len=f->relay_len;
    for(u32 i=0;i<f->relay_len;i++) o->relay[i]=f->relay[i];
    return h;
}
EXPORT u32 object_release(Session *s,u32 h) { Object *o=get(s,h); if(!o) return 0; o->kind=0; return 1; }
EXPORT int dial_target(Session *s,u32 h,u8 *p,u32 n) { Object *o=get(s,h); if(!o || !o->child || o->kind>3 || n>255) return -1; if(o->relay_len) { for(u32 i=0;i<o->relay_len;i++) p[i]=o->relay[i]; return o->relay_len; } return n; }
// Actions: 0 ready, (1<<16)|n send n bytes, (2<<16)|n read n bytes, -1 fail.
EXPORT int handshake(Session *s,u32 h,u8 *p,u32 n) {
    Object *o=get(s,h); if(!o || !o->child || o->kind>3) return -1;
    if(o->kind!=2) return 0;
    if(o->phase==0) { p[0]='O';p[1]='W';p[2]=VARIANT;p[3]=o->key; o->phase=1;return (1<<16)|4; }
    if(o->phase==1) { o->phase=2;return (2<<16)|4; }
    if(o->phase==2 && n==4 && p[0]=='O' && p[1]=='K' && p[2]==VARIANT && p[3]==o->key) { o->phase=3;return 0; }
    return -1;
}
EXPORT int write_limit(Session *s,u32 h,u32 n) { Object *o=get(s,h);if(!o || !o->child || o->kind>3) return -1; if(o->kind==3 && !o->written && n>o->key) return o->key;return n; }
EXPORT int transform(Session *s,u32 h,u32 encode,u8 *p,u32 n) {
    Object *o=get(s,h); if(!o || !o->child || n>MAX-4) return -1;
#if FAULT == 1
    for (;;) {} // Deliberate execution-budget fixture, never production code.
#elif FAULT == 2
    __builtin_trap(); // Deliberate trap fixture.
#endif
    if(o->kind<=3) { if(o->kind==2) for(u32 i=0;i<n;i++) p[i]^=(u8)(o->key ^ (VARIANT-1)); if(encode && n) o->written=1;return n; }
    if(o->kind==4) return n;
    if(encode) { for(u32 i=n;i>0;i--) p[i+3]=p[i-1]^(u8)(o->key ^ (VARIANT-1));p[0]='W';p[1]='P';p[2]=VARIANT;p[3]=o->key;return n+4; }
    if(n<4 || p[0]!='W' || p[1]!='P' || p[2]!=VARIANT || p[3]!=o->key) return -1;
    for(u32 i=4;i<n;i++) p[i-4]=p[i]^(u8)(o->key ^ (VARIANT-1));return n-4;
}
