#!/usr/bin/env python3
"""Dump uma lib nativa da memoria de um processo Android para um arquivo
onde file_offset == VA - base (formato que o Il2CppDumper espera em IsDumped)."""
import struct,subprocess,sys,os,collections,argparse

def sh(serial,cmd):
    r=subprocess.run(["adb","-s",serial,"shell",f"su -c '{cmd}'"],
                     capture_output=True,text=True)
    return r.stdout

def phdrs(path):
    d=open(path,'rb').read(0x2000)
    is64 = d[4]==2
    if is64:
        e_phoff,=struct.unpack_from("<Q",d,0x20)
        e_phentsize,e_phnum=struct.unpack_from("<HH",d,0x36)
        fmt,pick="<IIQQQQQQ",(0,2,3,5,6)      # type,off,va,filesz,memsz
    else:
        e_phoff,=struct.unpack_from("<I",d,0x1c)
        e_phentsize,e_phnum=struct.unpack_from("<HH",d,0x2a)
        fmt,pick="<IIIIIIII",(0,1,2,4,5)
    out=[]
    for i in range(e_phnum):
        f=struct.unpack_from(fmt,d,e_phoff+i*e_phentsize)
        t,off,va,fsz,msz=(f[j] for j in pick)
        if t==1: out.append((off,va,fsz,msz))
    return is64,out

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--serial",required=True); ap.add_argument("--pid",required=True)
    ap.add_argument("--lib",required=True,help="substring do nome no maps")
    ap.add_argument("--elf",required=True,help="copia do .so em disco (pros phdrs)")
    ap.add_argument("--out",required=True)
    a=ap.parse_args()

    is64,segs=phdrs(a.elf)
    print(f"ELF {'64' if is64 else '32'}-bit, {len(segs)} LOAD")
    maps=sh(a.serial,f"cat /proc/{a.pid}/maps")
    rows=[]
    for ln in maps.splitlines():
        p=ln.split()
        if len(p)<5: continue
        if a.lib not in ln and "[anon:.bss]" not in ln: continue
        lo,hi=[int(x,16) for x in p[0].split('-')]
        rows.append((lo,hi,int(p[2],16),p[1],ln))

    # base por consenso: para cada mapeamento file-backed, candidate = start - (p_vaddr & ~0xfff)
    votes=collections.Counter()
    for lo,hi,foff,perm,ln in rows:
        if a.lib not in ln: continue
        for off,va,fsz,msz in segs:
            if (off & ~0xfff)==foff: votes[lo-(va & ~0xfff)]+=1
    if not votes: sys.exit("nao achei mapeamentos da lib")
    base,n=votes.most_common(1)[0]
    print(f"base = {base:#x} (consenso {n}/{sum(votes.values())} votos; candidatos: "
          f"{[(hex(k),v) for k,v in votes.most_common(3)]})")

    # regioes a ler: mapeamentos da lib com a base certa + .bss adjacente
    keep=[]
    for lo,hi,foff,perm,ln in rows:
        rva=lo-base
        if rva<0: continue
        if a.lib in ln:
            ok=any((off & ~0xfff)==foff and (va & ~0xfff)==rva for off,va,fsz,msz in segs)
            if ok: keep.append((lo,hi,rva,"seg"))
        elif "[anon:.bss]" in ln and any(rva==( (va+fsz+0xfff)&~0xfff ) or
                 (va<=rva<va+msz) for off,va,fsz,msz in segs):
            keep.append((lo,hi,rva,"bss"))
    keep.sort()
    total=max(r+ (hi-lo) for lo,hi,r,_ in keep)
    print(f"imagem final: {total} bytes (0x{total:x}), {len(keep)} regioes")
    buf=bytearray(total)
    tmp=a.out+".part"
    for lo,hi,rva,kind in keep:
        n=hi-lo
        cmd=f"dd if=/proc/{a.pid}/mem bs=4096 skip={lo//0x1000} count={n//0x1000} 2>/dev/null"
        with open(tmp,'wb') as f:
            subprocess.run(["adb","-s",a.serial,"exec-out",f"su -c '{cmd}'"],
                           stdout=f,stderr=subprocess.DEVNULL)
        got=os.path.getsize(tmp)
        print(f"  {lo:#014x}-{hi:#014x} -> rva {rva:#010x} {n:>10}B {kind:4} {'OK' if got==n else f'!! {got}'}")
        buf[rva:rva+got]=open(tmp,'rb').read()
    os.remove(tmp)
    open(a.out,'wb').write(bytes(buf))
    print(f"\ngravado {a.out} ({os.path.getsize(a.out)} bytes)  ImageBase = {base:#x}")

main()
