<div align="center">

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=180&color=gradient&text=Ironveil&fontAlign=50&fontAlignY=35&fontSize=42&desc=Lua%20Obfuscation%20Engine%20•%20AST%20Transformations%20•%20Control%20Flow%20Hardening&descAlign=50&descAlignY=60" />

</div>

<p align="center">
<b>Ironveil is a Lua obfuscation engine built on AST transformations, designed to restructure and harden source code against reverse engineering.</b>
</p>

---

## ⚙️ Features

- AST-based transformation pipeline
- Control flow restructuring
- String / constant encoding layer
- Dead code injection system
- Variable rewriting / virtualization
- Lua 5.1 / LuaJIT support

---

## 🚀 Quick Start

```bash
git clone https://github.com/memcpython/ironveil.git
cd ironveil
npm install
npm run build
node dist/cli.js <input.lua|input.luau> [output.lua]
```
## 📥 Example

### Input

```lua
-- input.lua
print("Hello, World!");
```

### Obfuscated output

```lua
-- input.obfuscated.lua
return(function(...)return(function(...)local S,a,l,O,d,f,N,C,P,V,n,g,Z g={}Z={}g[1]=table.concat g[2]=table.insert g[3]=table.unpack or unpack g[4]=string.byte g[5]=string.char g[6]=string.sub g[7]=tonumber g[8]=type g[9]=rawget Z[1]=nil Z[2]={}Z[3]={}Z[4]={}Z[5]={}Z[6]={}Z[7]={}Z[8]={}Z[9]={}Z[12]=1 Z[13]=0 a={}l=nil O=nil Z[15]={}Z[16]=setmetatable({},{__mode="k"})Z[17]={}Z[18]=nil g[10]=function(U,L,r)return{[("l".."")]={},[("p".."")]=U,[("g".."")]=L,[("v".."")]=r or{[("n".."")]=0}}end g[11]=function(U)local L=Z[15][U]if L==nil then return U end return L end Z[17]={__len=function(U)return Z[16][U]or 0 end}g[13]=function(U,L)Z[16][U]=L return setmetatable(U,Z[17])end g[14]=function(U,L,r)local y=g[11](L)U[("l".."")][y]=r==nil and Z[2]or r end g[15]=function(U,L)local r=g[11](L)local y=U while y do local i=g[9](y[("l".."")],r)if i~=nil then if i==Z[2]then return nil,true end return i,true end y=y[("p".."")]end return nil,false end g[16]=function(U,L,r)local y=g[11](L)local i=U while i do local v=g[9](i[("l".."")],y)if v~=nil then i[("l".."")][y]=r==nil and Z[2]or r return end i=i[("p".."")]end U[("g".."")][y]=r end g[17]=function(U,L)local r=g[11](L)local y,i=g[15](U,L)if i then return y end return U[("g".."")][r]end g[12]=function(U,L)local r={}local y=0 for i=1,#U do local v=U[i]local w=v[1]if w==1 then y=y+1 local k=g[17](L,v[2])if k==nil then k=Z[2]end r[y]=k elseif w==2 then y=y+1 r[y]=g[51](v[2])elseif w==3 then y=y+1 r[y]=v[2]elseif w==4 then y=y+1 r[y]=v[2]==1 elseif w==5 then y=y+1 r[y]=Z[2]elseif w==6 then local k=r[y]if k==Z[2]then k=nil end local a=k[g[11](v[2])]if a==nil then a=Z[2]end r[y]=a elseif w==7 then local k=r[y]if k==Z[2]then k=nil end local a=r[y-1]if a==Z[2]then a=nil end local l=a[k]if l==nil then l=Z[2]end r[y-1]=l r[y]=nil y=y-1 elseif w==8 then local k=r[y]if k==Z[2]then k=nil end local a if v[2]==1 then a=-k elseif v[2]==2 then a=not k elseif v[2]==3 then a=#k elseif v[2]==4 then a=g[45](k)else error("iv")end if a==nil then a=Z[2]end r[y]=a elseif w==9 then local k=r[y]if k==Z[2]then k=nil end local a=r[y-1]if ...
-- remaining obfuscated output omitted
```

## 🧠 How It Works

Ironveil processes Lua code in multiple stages:

1. Parsing

Source code is converted into an AST (Abstract Syntax Tree).

2. Transformation Passes
control flow rewriting
variable renaming / virtualization
expression restructuring
3. Encoding Layer
strings and constants are encoded into runtime-decoded values
4. Code Generation

The transformed AST is compiled back into executable Lua bytecode-equivalent source.
⚠️ Warning

## Ironveil is designed for:

- code protection

- intellectual property obfuscation

- anti-analysis research


## 📜 License

[IronVeil License](https://github.com/memcpython/ironveil/blob/main/LICENSE)

<div align="center"> <img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=120&section=footer&color=gradient" /> </div>
