/* @qrauth/web-components v0.4.1 — https://qrauth.io */
"use strict";var QRAuthComponents=(()=>{var Oe=Object.create;var z=Object.defineProperty;var Ke=Object.getOwnPropertyDescriptor;var Ye=Object.getOwnPropertyNames;var Xe=Object.getPrototypeOf,Ge=Object.prototype.hasOwnProperty;var Je=(i,e,t)=>e in i?z(i,e,{enumerable:!0,configurable:!0,writable:!0,value:t}):i[e]=t;var g=(i,e)=>()=>(e||i((e={exports:{}}).exports,e),e.exports),We=(i,e)=>{for(var t in e)z(i,t,{get:e[t],enumerable:!0})},zt=(i,e,t,r)=>{if(e&&typeof e=="object"||typeof e=="function")for(let n of Ye(e))!Ge.call(i,n)&&n!==t&&z(i,n,{get:()=>e[n],enumerable:!(r=Ke(e,n))||r.enumerable});return i};var Ze=(i,e,t)=>(t=i!=null?Oe(Xe(i)):{},zt(e||!i||!i.__esModule?z(t,"default",{value:i,enumerable:!0}):t,i)),tr=i=>zt(z({},"__esModule",{value:!0}),i);var p=(i,e,t)=>Je(i,typeof e!="symbol"?e+"":e,t);var Qt=g((ri,Vt)=>{Vt.exports=function(){return typeof Promise=="function"&&Promise.prototype&&Promise.prototype.then}});var S=g(T=>{var mt,er=[0,26,44,70,100,134,172,196,242,292,346,404,466,532,581,655,733,815,901,991,1085,1156,1258,1364,1474,1588,1706,1828,1921,2051,2185,2323,2465,2611,2761,2876,3034,3196,3362,3532,3706];T.getSymbolSize=function(e){if(!e)throw new Error('"version" cannot be null or undefined');if(e<1||e>40)throw new Error('"version" should be in range from 1 to 40');return e*4+17};T.getSymbolTotalCodewords=function(e){return er[e]};T.getBCHDigit=function(i){let e=0;for(;i!==0;)e++,i>>>=1;return e};T.setToSJISFunction=function(e){if(typeof e!="function")throw new Error('"toSJISFunc" is not a valid function.');mt=e};T.isKanjiModeEnabled=function(){return typeof mt<"u"};T.toSJIS=function(e){return mt(e)}});var tt=g(v=>{v.L={bit:1};v.M={bit:0};v.Q={bit:3};v.H={bit:2};function rr(i){if(typeof i!="string")throw new Error("Param is not a string");switch(i.toLowerCase()){case"l":case"low":return v.L;case"m":case"medium":return v.M;case"q":case"quartile":return v.Q;case"h":case"high":return v.H;default:throw new Error("Unknown EC Level: "+i)}}v.isValid=function(e){return e&&typeof e.bit<"u"&&e.bit>=0&&e.bit<4};v.from=function(e,t){if(v.isValid(e))return e;try{return rr(e)}catch{return t}}});var Ot=g((si,jt)=>{function Ht(){this.buffer=[],this.length=0}Ht.prototype={get:function(i){let e=Math.floor(i/8);return(this.buffer[e]>>>7-i%8&1)===1},put:function(i,e){for(let t=0;t<e;t++)this.putBit((i>>>e-t-1&1)===1)},getLengthInBits:function(){return this.length},putBit:function(i){let e=Math.floor(this.length/8);this.buffer.length<=e&&this.buffer.push(0),i&&(this.buffer[e]|=128>>>this.length%8),this.length++}};jt.exports=Ht});var Yt=g((oi,Kt)=>{function V(i){if(!i||i<1)throw new Error("BitMatrix size must be defined and greater than 0");this.size=i,this.data=new Uint8Array(i*i),this.reservedBit=new Uint8Array(i*i)}V.prototype.set=function(i,e,t,r){let n=i*this.size+e;this.data[n]=t,r&&(this.reservedBit[n]=!0)};V.prototype.get=function(i,e){return this.data[i*this.size+e]};V.prototype.xor=function(i,e,t){this.data[i*this.size+e]^=t};V.prototype.isReserved=function(i,e){return this.reservedBit[i*this.size+e]};Kt.exports=V});var Xt=g(et=>{var ir=S().getSymbolSize;et.getRowColCoords=function(e){if(e===1)return[];let t=Math.floor(e/7)+2,r=ir(e),n=r===145?26:Math.ceil((r-13)/(2*t-2))*2,s=[r-7];for(let o=1;o<t-1;o++)s[o]=s[o-1]-n;return s.push(6),s.reverse()};et.getPositions=function(e){let t=[],r=et.getRowColCoords(e),n=r.length;for(let s=0;s<n;s++)for(let o=0;o<n;o++)s===0&&o===0||s===0&&o===n-1||s===n-1&&o===0||t.push([r[s],r[o]]);return t}});var Wt=g(Jt=>{var nr=S().getSymbolSize,Gt=7;Jt.getPositions=function(e){let t=nr(e);return[[0,0],[t-Gt,0],[0,t-Gt]]}});var Zt=g(m=>{m.Patterns={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7};var M={N1:3,N2:3,N3:40,N4:10};m.isValid=function(e){return e!=null&&e!==""&&!isNaN(e)&&e>=0&&e<=7};m.from=function(e){return m.isValid(e)?parseInt(e,10):void 0};m.getPenaltyN1=function(e){let t=e.size,r=0,n=0,s=0,o=null,a=null;for(let l=0;l<t;l++){n=s=0,o=a=null;for(let d=0;d<t;d++){let c=e.get(l,d);c===o?n++:(n>=5&&(r+=M.N1+(n-5)),o=c,n=1),c=e.get(d,l),c===a?s++:(s>=5&&(r+=M.N1+(s-5)),a=c,s=1)}n>=5&&(r+=M.N1+(n-5)),s>=5&&(r+=M.N1+(s-5))}return r};m.getPenaltyN2=function(e){let t=e.size,r=0;for(let n=0;n<t-1;n++)for(let s=0;s<t-1;s++){let o=e.get(n,s)+e.get(n,s+1)+e.get(n+1,s)+e.get(n+1,s+1);(o===4||o===0)&&r++}return r*M.N2};m.getPenaltyN3=function(e){let t=e.size,r=0,n=0,s=0;for(let o=0;o<t;o++){n=s=0;for(let a=0;a<t;a++)n=n<<1&2047|e.get(o,a),a>=10&&(n===1488||n===93)&&r++,s=s<<1&2047|e.get(a,o),a>=10&&(s===1488||s===93)&&r++}return r*M.N3};m.getPenaltyN4=function(e){let t=0,r=e.data.length;for(let s=0;s<r;s++)t+=e.data[s];return Math.abs(Math.ceil(t*100/r/5)-10)*M.N4};function sr(i,e,t){switch(i){case m.Patterns.PATTERN000:return(e+t)%2===0;case m.Patterns.PATTERN001:return e%2===0;case m.Patterns.PATTERN010:return t%3===0;case m.Patterns.PATTERN011:return(e+t)%3===0;case m.Patterns.PATTERN100:return(Math.floor(e/2)+Math.floor(t/3))%2===0;case m.Patterns.PATTERN101:return e*t%2+e*t%3===0;case m.Patterns.PATTERN110:return(e*t%2+e*t%3)%2===0;case m.Patterns.PATTERN111:return(e*t%3+(e+t)%2)%2===0;default:throw new Error("bad maskPattern:"+i)}}m.applyMask=function(e,t){let r=t.size;for(let n=0;n<r;n++)for(let s=0;s<r;s++)t.isReserved(s,n)||t.xor(s,n,sr(e,s,n))};m.getBestMask=function(e,t){let r=Object.keys(m.Patterns).length,n=0,s=1/0;for(let o=0;o<r;o++){t(o),m.applyMask(o,e);let a=m.getPenaltyN1(e)+m.getPenaltyN2(e)+m.getPenaltyN3(e)+m.getPenaltyN4(e);m.applyMask(o,e),a<s&&(s=a,n=o)}return n}});var vt=g(bt=>{var C=tt(),rt=[1,1,1,1,1,1,1,1,1,1,2,2,1,2,2,4,1,2,4,4,2,4,4,4,2,4,6,5,2,4,6,6,2,5,8,8,4,5,8,8,4,5,8,11,4,8,10,11,4,9,12,16,4,9,16,16,6,10,12,18,6,10,17,16,6,11,16,19,6,13,18,21,7,14,21,25,8,16,20,25,8,17,23,25,9,17,23,34,9,18,25,30,10,20,27,32,12,21,29,35,12,23,34,37,12,25,34,40,13,26,35,42,14,28,38,45,15,29,40,48,16,31,43,51,17,33,45,54,18,35,48,57,19,37,51,60,19,38,53,63,20,40,56,66,21,43,59,70,22,45,62,74,24,47,65,77,25,49,68,81],it=[7,10,13,17,10,16,22,28,15,26,36,44,20,36,52,64,26,48,72,88,36,64,96,112,40,72,108,130,48,88,132,156,60,110,160,192,72,130,192,224,80,150,224,264,96,176,260,308,104,198,288,352,120,216,320,384,132,240,360,432,144,280,408,480,168,308,448,532,180,338,504,588,196,364,546,650,224,416,600,700,224,442,644,750,252,476,690,816,270,504,750,900,300,560,810,960,312,588,870,1050,336,644,952,1110,360,700,1020,1200,390,728,1050,1260,420,784,1140,1350,450,812,1200,1440,480,868,1290,1530,510,924,1350,1620,540,980,1440,1710,570,1036,1530,1800,570,1064,1590,1890,600,1120,1680,1980,630,1204,1770,2100,660,1260,1860,2220,720,1316,1950,2310,750,1372,2040,2430];bt.getBlocksCount=function(e,t){switch(t){case C.L:return rt[(e-1)*4+0];case C.M:return rt[(e-1)*4+1];case C.Q:return rt[(e-1)*4+2];case C.H:return rt[(e-1)*4+3];default:return}};bt.getTotalCodewordsCount=function(e,t){switch(t){case C.L:return it[(e-1)*4+0];case C.M:return it[(e-1)*4+1];case C.Q:return it[(e-1)*4+2];case C.H:return it[(e-1)*4+3];default:return}}});var te=g(st=>{var Q=new Uint8Array(512),nt=new Uint8Array(256);(function(){let e=1;for(let t=0;t<255;t++)Q[t]=e,nt[e]=t,e<<=1,e&256&&(e^=285);for(let t=255;t<512;t++)Q[t]=Q[t-255]})();st.log=function(e){if(e<1)throw new Error("log("+e+")");return nt[e]};st.exp=function(e){return Q[e]};st.mul=function(e,t){return e===0||t===0?0:Q[nt[e]+nt[t]]}});var ee=g(H=>{var xt=te();H.mul=function(e,t){let r=new Uint8Array(e.length+t.length-1);for(let n=0;n<e.length;n++)for(let s=0;s<t.length;s++)r[n+s]^=xt.mul(e[n],t[s]);return r};H.mod=function(e,t){let r=new Uint8Array(e);for(;r.length-t.length>=0;){let n=r[0];for(let o=0;o<t.length;o++)r[o]^=xt.mul(t[o],n);let s=0;for(;s<r.length&&r[s]===0;)s++;r=r.slice(s)}return r};H.generateECPolynomial=function(e){let t=new Uint8Array([1]);for(let r=0;r<e;r++)t=H.mul(t,new Uint8Array([1,xt.exp(r)]));return t}});var ne=g((pi,ie)=>{var re=ee();function yt(i){this.genPoly=void 0,this.degree=i,this.degree&&this.initialize(this.degree)}yt.prototype.initialize=function(e){this.degree=e,this.genPoly=re.generateECPolynomial(this.degree)};yt.prototype.encode=function(e){if(!this.genPoly)throw new Error("Encoder not initialized");let t=new Uint8Array(e.length+this.degree);t.set(e);let r=re.mod(t,this.genPoly),n=this.degree-r.length;if(n>0){let s=new Uint8Array(this.degree);return s.set(r,n),s}return r};ie.exports=yt});var _t=g(se=>{se.isValid=function(e){return!isNaN(e)&&e>=1&&e<=40}});var wt=g(E=>{var oe="[0-9]+",or="[A-Z $%*+\\-./:]+",j="(?:[u3000-u303F]|[u3040-u309F]|[u30A0-u30FF]|[uFF00-uFFEF]|[u4E00-u9FAF]|[u2605-u2606]|[u2190-u2195]|u203B|[u2010u2015u2018u2019u2025u2026u201Cu201Du2225u2260]|[u0391-u0451]|[u00A7u00A8u00B1u00B4u00D7u00F7])+";j=j.replace(/u/g,"\\u");var ar="(?:(?![A-Z0-9 $%*+\\-./:]|"+j+`)(?:.|[\r
]))+`;E.KANJI=new RegExp(j,"g");E.BYTE_KANJI=new RegExp("[^A-Z0-9 $%*+\\-./:]+","g");E.BYTE=new RegExp(ar,"g");E.NUMERIC=new RegExp(oe,"g");E.ALPHANUMERIC=new RegExp(or,"g");var lr=new RegExp("^"+j+"$"),dr=new RegExp("^"+oe+"$"),cr=new RegExp("^[A-Z0-9 $%*+\\-./:]+$");E.testKanji=function(e){return lr.test(e)};E.testNumeric=function(e){return dr.test(e)};E.testAlphanumeric=function(e){return cr.test(e)}});var A=g(b=>{var ur=_t(),Et=wt();b.NUMERIC={id:"Numeric",bit:1,ccBits:[10,12,14]};b.ALPHANUMERIC={id:"Alphanumeric",bit:2,ccBits:[9,11,13]};b.BYTE={id:"Byte",bit:4,ccBits:[8,16,16]};b.KANJI={id:"Kanji",bit:8,ccBits:[8,10,12]};b.MIXED={bit:-1};b.getCharCountIndicator=function(e,t){if(!e.ccBits)throw new Error("Invalid mode: "+e);if(!ur.isValid(t))throw new Error("Invalid version: "+t);return t>=1&&t<10?e.ccBits[0]:t<27?e.ccBits[1]:e.ccBits[2]};b.getBestModeForData=function(e){return Et.testNumeric(e)?b.NUMERIC:Et.testAlphanumeric(e)?b.ALPHANUMERIC:Et.testKanji(e)?b.KANJI:b.BYTE};b.toString=function(e){if(e&&e.id)return e.id;throw new Error("Invalid mode")};b.isValid=function(e){return e&&e.bit&&e.ccBits};function hr(i){if(typeof i!="string")throw new Error("Param is not a string");switch(i.toLowerCase()){case"numeric":return b.NUMERIC;case"alphanumeric":return b.ALPHANUMERIC;case"kanji":return b.KANJI;case"byte":return b.BYTE;default:throw new Error("Unknown mode: "+i)}}b.from=function(e,t){if(b.isValid(e))return e;try{return hr(e)}catch{return t}}});var ue=g(R=>{var ot=S(),pr=vt(),ae=tt(),B=A(),kt=_t(),de=7973,le=ot.getBCHDigit(de);function gr(i,e,t){for(let r=1;r<=40;r++)if(e<=R.getCapacity(r,t,i))return r}function ce(i,e){return B.getCharCountIndicator(i,e)+4}function fr(i,e){let t=0;return i.forEach(function(r){let n=ce(r.mode,e);t+=n+r.getBitsLength()}),t}function mr(i,e){for(let t=1;t<=40;t++)if(fr(i,t)<=R.getCapacity(t,e,B.MIXED))return t}R.from=function(e,t){return kt.isValid(e)?parseInt(e,10):t};R.getCapacity=function(e,t,r){if(!kt.isValid(e))throw new Error("Invalid QR Code version");typeof r>"u"&&(r=B.BYTE);let n=ot.getSymbolTotalCodewords(e),s=pr.getTotalCodewordsCount(e,t),o=(n-s)*8;if(r===B.MIXED)return o;let a=o-ce(r,e);switch(r){case B.NUMERIC:return Math.floor(a/10*3);case B.ALPHANUMERIC:return Math.floor(a/11*2);case B.KANJI:return Math.floor(a/13);case B.BYTE:default:return Math.floor(a/8)}};R.getBestVersionForData=function(e,t){let r,n=ae.from(t,ae.M);if(Array.isArray(e)){if(e.length>1)return mr(e,n);if(e.length===0)return 1;r=e[0]}else r=e;return gr(r.mode,r.getLength(),n)};R.getEncodedBits=function(e){if(!kt.isValid(e)||e<7)throw new Error("Invalid QR Code version");let t=e<<12;for(;ot.getBCHDigit(t)-le>=0;)t^=de<<ot.getBCHDigit(t)-le;return e<<12|t}});var fe=g(ge=>{var It=S(),pe=1335,br=21522,he=It.getBCHDigit(pe);ge.getEncodedBits=function(e,t){let r=e.bit<<3|t,n=r<<10;for(;It.getBCHDigit(n)-he>=0;)n^=pe<<It.getBCHDigit(n)-he;return(r<<10|n)^br}});var be=g((xi,me)=>{var vr=A();function N(i){this.mode=vr.NUMERIC,this.data=i.toString()}N.getBitsLength=function(e){return 10*Math.floor(e/3)+(e%3?e%3*3+1:0)};N.prototype.getLength=function(){return this.data.length};N.prototype.getBitsLength=function(){return N.getBitsLength(this.data.length)};N.prototype.write=function(e){let t,r,n;for(t=0;t+3<=this.data.length;t+=3)r=this.data.substr(t,3),n=parseInt(r,10),e.put(n,10);let s=this.data.length-t;s>0&&(r=this.data.substr(t),n=parseInt(r,10),e.put(n,s*3+1))};me.exports=N});var xe=g((yi,ve)=>{var xr=A(),St=["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"," ","$","%","*","+","-",".","/",":"];function D(i){this.mode=xr.ALPHANUMERIC,this.data=i}D.getBitsLength=function(e){return 11*Math.floor(e/2)+6*(e%2)};D.prototype.getLength=function(){return this.data.length};D.prototype.getBitsLength=function(){return D.getBitsLength(this.data.length)};D.prototype.write=function(e){let t;for(t=0;t+2<=this.data.length;t+=2){let r=St.indexOf(this.data[t])*45;r+=St.indexOf(this.data[t+1]),e.put(r,11)}this.data.length%2&&e.put(St.indexOf(this.data[t]),6)};ve.exports=D});var _e=g((_i,ye)=>{var yr=A();function U(i){this.mode=yr.BYTE,typeof i=="string"?this.data=new TextEncoder().encode(i):this.data=new Uint8Array(i)}U.getBitsLength=function(e){return e*8};U.prototype.getLength=function(){return this.data.length};U.prototype.getBitsLength=function(){return U.getBitsLength(this.data.length)};U.prototype.write=function(i){for(let e=0,t=this.data.length;e<t;e++)i.put(this.data[e],8)};ye.exports=U});var Ee=g((wi,we)=>{var _r=A(),wr=S();function L(i){this.mode=_r.KANJI,this.data=i}L.getBitsLength=function(e){return e*13};L.prototype.getLength=function(){return this.data.length};L.prototype.getBitsLength=function(){return L.getBitsLength(this.data.length)};L.prototype.write=function(i){let e;for(e=0;e<this.data.length;e++){let t=wr.toSJIS(this.data[e]);if(t>=33088&&t<=40956)t-=33088;else if(t>=57408&&t<=60351)t-=49472;else throw new Error("Invalid SJIS character: "+this.data[e]+`
Make sure your charset is UTF-8`);t=(t>>>8&255)*192+(t&255),i.put(t,13)}};we.exports=L});var ke=g((Ei,Ct)=>{"use strict";var O={single_source_shortest_paths:function(i,e,t){var r={},n={};n[e]=0;var s=O.PriorityQueue.make();s.push(e,0);for(var o,a,l,d,c,u,f,x,k;!s.empty();){o=s.pop(),a=o.value,d=o.cost,c=i[a]||{};for(l in c)c.hasOwnProperty(l)&&(u=c[l],f=d+u,x=n[l],k=typeof n[l]>"u",(k||x>f)&&(n[l]=f,s.push(l,f),r[l]=a))}if(typeof t<"u"&&typeof n[t]>"u"){var I=["Could not find a path from ",e," to ",t,"."].join("");throw new Error(I)}return r},extract_shortest_path_from_predecessor_list:function(i,e){for(var t=[],r=e,n;r;)t.push(r),n=i[r],r=i[r];return t.reverse(),t},find_path:function(i,e,t){var r=O.single_source_shortest_paths(i,e,t);return O.extract_shortest_path_from_predecessor_list(r,t)},PriorityQueue:{make:function(i){var e=O.PriorityQueue,t={},r;i=i||{};for(r in e)e.hasOwnProperty(r)&&(t[r]=e[r]);return t.queue=[],t.sorter=i.sorter||e.default_sorter,t},default_sorter:function(i,e){return i.cost-e.cost},push:function(i,e){var t={value:i,cost:e};this.queue.push(t),this.queue.sort(this.sorter)},pop:function(){return this.queue.shift()},empty:function(){return this.queue.length===0}}};typeof Ct<"u"&&(Ct.exports=O)});var Re=g(F=>{var h=A(),Ce=be(),Ae=xe(),Be=_e(),Te=Ee(),K=wt(),at=S(),Er=ke();function Ie(i){return unescape(encodeURIComponent(i)).length}function Y(i,e,t){let r=[],n;for(;(n=i.exec(t))!==null;)r.push({data:n[0],index:n.index,mode:e,length:n[0].length});return r}function Me(i){let e=Y(K.NUMERIC,h.NUMERIC,i),t=Y(K.ALPHANUMERIC,h.ALPHANUMERIC,i),r,n;return at.isKanjiModeEnabled()?(r=Y(K.BYTE,h.BYTE,i),n=Y(K.KANJI,h.KANJI,i)):(r=Y(K.BYTE_KANJI,h.BYTE,i),n=[]),e.concat(t,r,n).sort(function(o,a){return o.index-a.index}).map(function(o){return{data:o.data,mode:o.mode,length:o.length}})}function At(i,e){switch(e){case h.NUMERIC:return Ce.getBitsLength(i);case h.ALPHANUMERIC:return Ae.getBitsLength(i);case h.KANJI:return Te.getBitsLength(i);case h.BYTE:return Be.getBitsLength(i)}}function kr(i){return i.reduce(function(e,t){let r=e.length-1>=0?e[e.length-1]:null;return r&&r.mode===t.mode?(e[e.length-1].data+=t.data,e):(e.push(t),e)},[])}function Ir(i){let e=[];for(let t=0;t<i.length;t++){let r=i[t];switch(r.mode){case h.NUMERIC:e.push([r,{data:r.data,mode:h.ALPHANUMERIC,length:r.length},{data:r.data,mode:h.BYTE,length:r.length}]);break;case h.ALPHANUMERIC:e.push([r,{data:r.data,mode:h.BYTE,length:r.length}]);break;case h.KANJI:e.push([r,{data:r.data,mode:h.BYTE,length:Ie(r.data)}]);break;case h.BYTE:e.push([{data:r.data,mode:h.BYTE,length:Ie(r.data)}])}}return e}function Sr(i,e){let t={},r={start:{}},n=["start"];for(let s=0;s<i.length;s++){let o=i[s],a=[];for(let l=0;l<o.length;l++){let d=o[l],c=""+s+l;a.push(c),t[c]={node:d,lastCount:0},r[c]={};for(let u=0;u<n.length;u++){let f=n[u];t[f]&&t[f].node.mode===d.mode?(r[f][c]=At(t[f].lastCount+d.length,d.mode)-At(t[f].lastCount,d.mode),t[f].lastCount+=d.length):(t[f]&&(t[f].lastCount=d.length),r[f][c]=At(d.length,d.mode)+4+h.getCharCountIndicator(d.mode,e))}}n=a}for(let s=0;s<n.length;s++)r[n[s]].end=0;return{map:r,table:t}}function Se(i,e){let t,r=h.getBestModeForData(i);if(t=h.from(e,r),t!==h.BYTE&&t.bit<r.bit)throw new Error('"'+i+'" cannot be encoded with mode '+h.toString(t)+`.
 Suggested mode is: `+h.toString(r));switch(t===h.KANJI&&!at.isKanjiModeEnabled()&&(t=h.BYTE),t){case h.NUMERIC:return new Ce(i);case h.ALPHANUMERIC:return new Ae(i);case h.KANJI:return new Te(i);case h.BYTE:return new Be(i)}}F.fromArray=function(e){return e.reduce(function(t,r){return typeof r=="string"?t.push(Se(r,null)):r.data&&t.push(Se(r.data,r.mode)),t},[])};F.fromString=function(e,t){let r=Me(e,at.isKanjiModeEnabled()),n=Ir(r),s=Sr(n,t),o=Er.find_path(s.map,"start","end"),a=[];for(let l=1;l<o.length-1;l++)a.push(s.table[o[l]].node);return F.fromArray(kr(a))};F.rawSplit=function(e){return F.fromArray(Me(e,at.isKanjiModeEnabled()))}});var qe=g(Pe=>{var dt=S(),Bt=tt(),Cr=Ot(),Ar=Yt(),Br=Xt(),Tr=Wt(),Rt=Zt(),Pt=vt(),Mr=ne(),lt=ue(),Rr=fe(),Pr=A(),Tt=Re();function qr(i,e){let t=i.size,r=Tr.getPositions(e);for(let n=0;n<r.length;n++){let s=r[n][0],o=r[n][1];for(let a=-1;a<=7;a++)if(!(s+a<=-1||t<=s+a))for(let l=-1;l<=7;l++)o+l<=-1||t<=o+l||(a>=0&&a<=6&&(l===0||l===6)||l>=0&&l<=6&&(a===0||a===6)||a>=2&&a<=4&&l>=2&&l<=4?i.set(s+a,o+l,!0,!0):i.set(s+a,o+l,!1,!0))}}function Nr(i){let e=i.size;for(let t=8;t<e-8;t++){let r=t%2===0;i.set(t,6,r,!0),i.set(6,t,r,!0)}}function Dr(i,e){let t=Br.getPositions(e);for(let r=0;r<t.length;r++){let n=t[r][0],s=t[r][1];for(let o=-2;o<=2;o++)for(let a=-2;a<=2;a++)o===-2||o===2||a===-2||a===2||o===0&&a===0?i.set(n+o,s+a,!0,!0):i.set(n+o,s+a,!1,!0)}}function Ur(i,e){let t=i.size,r=lt.getEncodedBits(e),n,s,o;for(let a=0;a<18;a++)n=Math.floor(a/3),s=a%3+t-8-3,o=(r>>a&1)===1,i.set(n,s,o,!0),i.set(s,n,o,!0)}function Mt(i,e,t){let r=i.size,n=Rr.getEncodedBits(e,t),s,o;for(s=0;s<15;s++)o=(n>>s&1)===1,s<6?i.set(s,8,o,!0):s<8?i.set(s+1,8,o,!0):i.set(r-15+s,8,o,!0),s<8?i.set(8,r-s-1,o,!0):s<9?i.set(8,15-s-1+1,o,!0):i.set(8,15-s-1,o,!0);i.set(r-8,8,1,!0)}function Lr(i,e){let t=i.size,r=-1,n=t-1,s=7,o=0;for(let a=t-1;a>0;a-=2)for(a===6&&a--;;){for(let l=0;l<2;l++)if(!i.isReserved(n,a-l)){let d=!1;o<e.length&&(d=(e[o]>>>s&1)===1),i.set(n,a-l,d),s--,s===-1&&(o++,s=7)}if(n+=r,n<0||t<=n){n-=r,r=-r;break}}}function Fr(i,e,t){let r=new Cr;t.forEach(function(l){r.put(l.mode.bit,4),r.put(l.getLength(),Pr.getCharCountIndicator(l.mode,i)),l.write(r)});let n=dt.getSymbolTotalCodewords(i),s=Pt.getTotalCodewordsCount(i,e),o=(n-s)*8;for(r.getLengthInBits()+4<=o&&r.put(0,4);r.getLengthInBits()%8!==0;)r.putBit(0);let a=(o-r.getLengthInBits())/8;for(let l=0;l<a;l++)r.put(l%2?17:236,8);return $r(r,i,e)}function $r(i,e,t){let r=dt.getSymbolTotalCodewords(e),n=Pt.getTotalCodewordsCount(e,t),s=r-n,o=Pt.getBlocksCount(e,t),a=r%o,l=o-a,d=Math.floor(r/o),c=Math.floor(s/o),u=c+1,f=d-c,x=new Mr(f),k=0,I=new Array(o),Ft=new Array(o),pt=0,je=new Uint8Array(i.buffer);for(let q=0;q<o;q++){let ft=q<l?c:u;I[q]=je.slice(k,k+ft),Ft[q]=x.encode(I[q]),k+=ft,pt=Math.max(pt,ft)}let gt=new Uint8Array(r),$t=0,_,w;for(_=0;_<pt;_++)for(w=0;w<o;w++)_<I[w].length&&(gt[$t++]=I[w][_]);for(_=0;_<f;_++)for(w=0;w<o;w++)gt[$t++]=Ft[w][_];return gt}function zr(i,e,t,r){let n;if(Array.isArray(i))n=Tt.fromArray(i);else if(typeof i=="string"){let d=e;if(!d){let c=Tt.rawSplit(i);d=lt.getBestVersionForData(c,t)}n=Tt.fromString(i,d||40)}else throw new Error("Invalid data");let s=lt.getBestVersionForData(n,t);if(!s)throw new Error("The amount of data is too big to be stored in a QR Code");if(!e)e=s;else if(e<s)throw new Error(`
The chosen QR Code version cannot contain this amount of data.
Minimum version required to store current data is: `+s+`.
`);let o=Fr(e,t,n),a=dt.getSymbolSize(e),l=new Ar(a);return qr(l,e),Nr(l),Dr(l,e),Mt(l,t,0),e>=7&&Ur(l,e),Lr(l,o),isNaN(r)&&(r=Rt.getBestMask(l,Mt.bind(null,l,t))),Rt.applyMask(r,l),Mt(l,t,r),{modules:l,version:e,errorCorrectionLevel:t,maskPattern:r,segments:n}}Pe.create=function(e,t){if(typeof e>"u"||e==="")throw new Error("No input text");let r=Bt.M,n,s;return typeof t<"u"&&(r=Bt.from(t.errorCorrectionLevel,Bt.M),n=lt.from(t.version),s=Rt.from(t.maskPattern),t.toSJISFunc&&dt.setToSJISFunction(t.toSJISFunc)),zr(e,n,r,s)}});var qt=g(P=>{function Ne(i){if(typeof i=="number"&&(i=i.toString()),typeof i!="string")throw new Error("Color should be defined as hex string");let e=i.slice().replace("#","").split("");if(e.length<3||e.length===5||e.length>8)throw new Error("Invalid hex color: "+i);(e.length===3||e.length===4)&&(e=Array.prototype.concat.apply([],e.map(function(r){return[r,r]}))),e.length===6&&e.push("F","F");let t=parseInt(e.join(""),16);return{r:t>>24&255,g:t>>16&255,b:t>>8&255,a:t&255,hex:"#"+e.slice(0,6).join("")}}P.getOptions=function(e){e||(e={}),e.color||(e.color={});let t=typeof e.margin>"u"||e.margin===null||e.margin<0?4:e.margin,r=e.width&&e.width>=21?e.width:void 0,n=e.scale||4;return{width:r,scale:r?4:n,margin:t,color:{dark:Ne(e.color.dark||"#000000ff"),light:Ne(e.color.light||"#ffffffff")},type:e.type,rendererOpts:e.rendererOpts||{}}};P.getScale=function(e,t){return t.width&&t.width>=e+t.margin*2?t.width/(e+t.margin*2):t.scale};P.getImageWidth=function(e,t){let r=P.getScale(e,t);return Math.floor((e+t.margin*2)*r)};P.qrToImageData=function(e,t,r){let n=t.modules.size,s=t.modules.data,o=P.getScale(n,r),a=Math.floor((n+r.margin*2)*o),l=r.margin*o,d=[r.color.light,r.color.dark];for(let c=0;c<a;c++)for(let u=0;u<a;u++){let f=(c*a+u)*4,x=r.color.light;if(c>=l&&u>=l&&c<a-l&&u<a-l){let k=Math.floor((c-l)/o),I=Math.floor((u-l)/o);x=d[s[k*n+I]?1:0]}e[f++]=x.r,e[f++]=x.g,e[f++]=x.b,e[f]=x.a}}});var De=g(ct=>{var Nt=qt();function Vr(i,e,t){i.clearRect(0,0,e.width,e.height),e.style||(e.style={}),e.height=t,e.width=t,e.style.height=t+"px",e.style.width=t+"px"}function Qr(){try{return document.createElement("canvas")}catch{throw new Error("You need to specify a canvas element")}}ct.render=function(e,t,r){let n=r,s=t;typeof n>"u"&&(!t||!t.getContext)&&(n=t,t=void 0),t||(s=Qr()),n=Nt.getOptions(n);let o=Nt.getImageWidth(e.modules.size,n),a=s.getContext("2d"),l=a.createImageData(o,o);return Nt.qrToImageData(l.data,e,n),Vr(a,s,o),a.putImageData(l,0,0),s};ct.renderToDataURL=function(e,t,r){let n=r;typeof n>"u"&&(!t||!t.getContext)&&(n=t,t=void 0),n||(n={});let s=ct.render(e,t,n),o=n.type||"image/png",a=n.rendererOpts||{};return s.toDataURL(o,a.quality)}});var Fe=g(Le=>{var Hr=qt();function Ue(i,e){let t=i.a/255,r=e+'="'+i.hex+'"';return t<1?r+" "+e+'-opacity="'+t.toFixed(2).slice(1)+'"':r}function Dt(i,e,t){let r=i+e;return typeof t<"u"&&(r+=" "+t),r}function jr(i,e,t){let r="",n=0,s=!1,o=0;for(let a=0;a<i.length;a++){let l=Math.floor(a%e),d=Math.floor(a/e);!l&&!s&&(s=!0),i[a]?(o++,a>0&&l>0&&i[a-1]||(r+=s?Dt("M",l+t,.5+d+t):Dt("m",n,0),n=0,s=!1),l+1<e&&i[a+1]||(r+=Dt("h",o),o=0)):n++}return r}Le.render=function(e,t,r){let n=Hr.getOptions(t),s=e.modules.size,o=e.modules.data,a=s+n.margin*2,l=n.color.light.a?"<path "+Ue(n.color.light,"fill")+' d="M0 0h'+a+"v"+a+'H0z"/>':"",d="<path "+Ue(n.color.dark,"stroke")+' d="'+jr(o,s,n.margin)+'"/>',c='viewBox="0 0 '+a+" "+a+'"',f='<svg xmlns="http://www.w3.org/2000/svg" '+(n.width?'width="'+n.width+'" height="'+n.width+'" ':"")+c+' shape-rendering="crispEdges">'+l+d+`</svg>
`;return typeof r=="function"&&r(null,f),f}});var ze=g(X=>{var Or=Qt(),Ut=qe(),$e=De(),Kr=Fe();function Lt(i,e,t,r,n){let s=[].slice.call(arguments,1),o=s.length,a=typeof s[o-1]=="function";if(!a&&!Or())throw new Error("Callback required as last argument");if(a){if(o<2)throw new Error("Too few arguments provided");o===2?(n=t,t=e,e=r=void 0):o===3&&(e.getContext&&typeof n>"u"?(n=r,r=void 0):(n=r,r=t,t=e,e=void 0))}else{if(o<1)throw new Error("Too few arguments provided");return o===1?(t=e,e=r=void 0):o===2&&!e.getContext&&(r=t,t=e,e=void 0),new Promise(function(l,d){try{let c=Ut.create(t,r);l(i(c,e,r))}catch(c){d(c)}})}try{let l=Ut.create(t,r);n(null,i(l,e,r))}catch(l){n(l)}}X.create=Ut.create;X.toCanvas=Lt.bind(null,$e.render);X.toDataURL=Lt.bind(null,$e.renderToDataURL);X.toString=Lt.bind(null,function(i,e,t){return Kr.render(i,t)})});var Wr={};We(Wr,{QRAuthElement:()=>y,QRAuthEphemeral:()=>W,QRAuthLogin:()=>J,QRAuthTwoFA:()=>Z});var y=class extends HTMLElement{constructor(){super();p(this,"shadow");p(this,"_sseConnection",null);p(this,"_pollInterval",null);this.shadow=this.attachShadow({mode:"open"})}static get observedAttributes(){return["tenant","theme","base-url","force-mode","mobile-fallback-only"]}get tenant(){return this.getAttribute("tenant")||""}get theme(){return this.getAttribute("theme")||"light"}get baseUrl(){let t=this.getAttribute("base-url");return t!==null?t:"https://qrauth.io"}connectedCallback(){this.render()}disconnectedCallback(){this.cleanup()}attributeChangedCallback(t,r,n){r!==n&&this.render()}isMobileLike(){if(typeof window>"u")return!1;let t=this.getAttribute("force-mode");if(t==="mobile")return!0;if(t==="desktop"||this.hasAttribute("mobile-fallback-only"))return!1;if(typeof window.matchMedia=="function"){let r=window.matchMedia("(pointer: coarse)").matches,n=window.matchMedia("(hover: none)").matches;if(r&&n)return!0}return/Android|iPhone|iPad|iPod|Mobile|Tablet|BlackBerry|Opera Mini/i.test(navigator.userAgent)}connectSSE(t){this.disconnectSSE(),this._sseConnection=new EventSource(t),this._sseConnection.onerror=()=>{this.disconnectSSE()}}onSSEEvent(t,r){this._sseConnection&&this._sseConnection.addEventListener(t,n=>{let s=n;try{r(JSON.parse(s.data))}catch{}})}disconnectSSE(){this._sseConnection&&(this._sseConnection.close(),this._sseConnection=null)}startPolling(t,r,n,s){this.stopPolling();let o=async()=>{try{let a=await fetch(t,{headers:s});a.ok&&n(await a.json())}catch{}};o(),this._pollInterval=setInterval(o,r)}stopPolling(){this._pollInterval&&(clearInterval(this._pollInterval),this._pollInterval=null)}cleanup(){this.disconnectSSE(),this.stopPolling()}emit(t,r){this.dispatchEvent(new CustomEvent(t,{bubbles:!0,composed:!0,detail:r}))}async generateCodeVerifier(){let t=new Uint8Array(32);return crypto.getRandomValues(t),this._base64url(t)}async computeCodeChallenge(t){let n=new TextEncoder().encode(t),s=await crypto.subtle.digest("SHA-256",n);return this._base64url(new Uint8Array(s))}_base64url(t){let r=Array.from(t,n=>String.fromCodePoint(n)).join("");return btoa(r).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}getBaseStyles(){return`
      :host {
        display: inline-block;
        font-family: var(--qrauth-font, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif);
        --_primary:       var(--qrauth-primary, #00a76f);
        --_primary-dark:  var(--qrauth-primary-dark, #007a52);
        --_text:          var(--qrauth-text, #1a1a2e);
        --_text-muted:    var(--qrauth-text-muted, #637381);
        --_bg:            var(--qrauth-bg, #ffffff);
        --_surface:       var(--qrauth-surface, #f9fafb);
        --_border:        var(--qrauth-border, #e0e0e0);
        --_radius:        var(--qrauth-radius, 12px);
        --_shadow:        var(--qrauth-shadow, 0 24px 48px rgba(0,0,0,0.15));
        --_btn-bg:        var(--qrauth-btn-bg, #1b2a4a);
        --_btn-hover:     var(--qrauth-btn-hover, #263b66);
        --_success:       #00a76f;
        --_error:         #ff5630;
        --_warning:       #ffab00;
        --_disabled:      #919eab;
      }
      :host([theme="dark"]) {
        --_text:       var(--qrauth-text, #f0f0f0);
        --_text-muted: var(--qrauth-text-muted, #919eab);
        --_bg:         var(--qrauth-bg, #1a1a2e);
        --_surface:    var(--qrauth-surface, #242436);
        --_border:     var(--qrauth-border, rgba(255,255,255,0.12));
        --_shadow:     var(--qrauth-shadow, 0 24px 48px rgba(0,0,0,0.5));
        --_btn-bg:     var(--qrauth-btn-bg, #263b66);
        --_btn-hover:  var(--qrauth-btn-hover, #2e4578);
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
    `}};var Ve=Ze(ze(),1);function $(i,e=440){if(!i)return"";let t=Math.max(1,Math.floor(Number.isFinite(e)?e:440)),r;try{r=Ve.default.create(i,{errorCorrectionLevel:"M"})}catch{return""}let n=r.modules,s=4,o=n.size+s*2,a=t/o,l="";for(let d=0;d<n.size;d++)for(let c=0;c<n.size;c++)if(n.data[d*n.size+c]){let u=(c+s)*a,f=(d+s)*a;l+=`<rect x="${u.toFixed(2)}" y="${f.toFixed(2)}" width="${a.toFixed(2)}" height="${a.toFixed(2)}"/>`}return`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${t} ${t}" width="${t}" height="${t}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="100%" height="100%" fill="#ffffff"/><g fill="#000000">${l}</g></svg>`}var G=`<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z"
        fill="none" stroke="#fff" stroke-width="5"/>
  <g fill="#fff" opacity="0.2">
    <rect x="52" y="40" width="18" height="18" rx="3"/>
    <rect x="78" y="40" width="18" height="18" rx="3"/>
    <rect x="130" y="40" width="18" height="18" rx="3"/>
    <rect x="52" y="66" width="18" height="18" rx="3"/>
    <rect x="104" y="66" width="18" height="18" rx="3"/>
    <rect x="78" y="92" width="18" height="18" rx="3"/>
    <rect x="130" y="92" width="18" height="18" rx="3"/>
    <rect x="52" y="118" width="18" height="18" rx="3"/>
    <rect x="104" y="118" width="18" height="18" rx="3"/>
  </g>
  <path d="M62 104 L88 134 L144 64"
        fill="none" stroke="#fff" stroke-width="15"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`,Qe=`<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="currentColor"/>
</svg>`,Yr=`<svg class="spinner" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2.5"
          stroke-dasharray="31.416" stroke-dashoffset="10" stroke-linecap="round"/>
</svg>`,J=class extends y{constructor(){super(...arguments);p(this,"_sessionId",null);p(this,"_sessionToken",null);p(this,"_codeVerifier",null);p(this,"_status","idle");p(this,"_expiresAt",null);p(this,"_currentQrUrl",null);p(this,"_timerInterval",null);p(this,"_pollTimeout",null)}static get observedAttributes(){return[...super.observedAttributes,"scopes","redirect-url","on-auth","display","animated","redirect-uri"]}get scopes(){return this.getAttribute("scopes")||"identity"}get redirectUrl(){return this.getAttribute("redirect-url")}get onAuth(){return this.getAttribute("on-auth")}get display(){return this.getAttribute("display")||"button"}get animated(){return this.hasAttribute("animated")}get redirectUri(){return this.getAttribute("redirect-uri")}get forceMode(){let t=this.getAttribute("force-mode");return t==="mobile"||t==="desktop"?t:"auto"}get mobileFallbackOnly(){return this.hasAttribute("mobile-fallback-only")}disconnectedCallback(){super.disconnectedCallback(),this._clearTimers()}render(){this.display==="inline"?this._renderInline():this._renderButton()}_renderButton(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: inline-block; }

        .btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          user-select: none;
          line-height: 1.4;
          font-family: inherit;
        }
        .btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .btn:active:not(:disabled) { transform: translateY(0); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        /* Modal overlay */
        .overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.55);
          z-index: 99999;
          display: flex;
          align-items: center;
          justify-content: center;
          animation: fade-in 0.2s ease;
        }
        .overlay.hidden { display: none; }

        @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slide-up {
          from { transform: translateY(24px); opacity: 0; }
          to   { transform: translateY(0); opacity: 1; }
        }

        .modal {
          background: var(--_bg);
          border-radius: 16px;
          padding: 32px 28px 24px;
          max-width: 380px;
          width: 90vw;
          box-shadow: var(--_shadow);
          text-align: center;
          animation: slide-up 0.3s ease;
          position: relative;
        }

        ${this._sharedModalStyles()}
      </style>

      <button class="btn" id="open-btn" aria-label="Sign in with QRAuth">
        <span class="btn-icon">${G}</span>
        Sign in with QRAuth
      </button>

      <div class="overlay hidden" id="overlay" role="dialog" aria-modal="true" aria-label="QRAuth sign-in">
        <div class="modal">
          ${this._modalContent()}
        </div>
      </div>
    `,this._bindButtonEvents()}_renderInline(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .inline-container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 28px 24px 20px;
          text-align: center;
          max-width: 360px;
          margin: 0 auto;
        }

        /* Idle state: show start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
        }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        ${this._sharedModalStyles()}
      </style>

      <div class="inline-container">
        <div id="inline-body">
          ${this._inlineIdleContent()}
        </div>
      </div>
    `,this._bindInlineEvents()}_inlineIdleContent(){return`
      <button class="start-btn" id="start-btn" aria-label="Sign in with QRAuth">
        <span class="btn-icon">${G}</span>
        Sign in with QRAuth
      </button>
    `}_modalContent(){return`
      <button class="close-btn" id="close-btn" aria-label="Close">&times;</button>
      <div id="modal-body">
        ${this._bodyForStatus("idle")}
      </div>
    `}_bodyForStatus(t,r){switch(t){case"idle":return`
          <div class="state-header">
            <div class="brand-icon">${G}</div>
            <h3>Sign in with QRAuth</h3>
            <p>Secure, passwordless authentication</p>
          </div>
        `;case"loading":return`
          <div class="state-loading">
            <div class="spinner-wrap">${Yr}</div>
            <p class="status-text">Generating QR code...</p>
          </div>
        `;case"pending":case"SCANNED":{if(this.isMobileLike())return this._mobilePendingBody(t,r);let n=t==="SCANNED";return`
          <h3>Sign in with QRAuth</h3>
          <p class="subtitle">Scan this QR code with your phone camera</p>
          ${this._qrFrameHtml(r?.qrUrl??"",n)}
          <div class="status-text ${n?"status-scanned":""}">
            ${n?"&#10003; QR code scanned &mdash; waiting for approval...":"Waiting for scan..."}
          </div>
          <div class="timer" id="timer">${r?.timerHtml??""}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `}case"APPROVED":return`
          <div class="state-approved">
            <div class="success-icon">${Qe}</div>
            <h3>Identity verified!</h3>
            <p class="subtitle">You are now signed in</p>
          </div>
        `;case"DENIED":return`
          <div class="state-denied">
            <div class="error-icon">&#10007;</div>
            <h3>Authentication denied</h3>
            <p class="subtitle">The request was declined on your device.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"EXPIRED":return`
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Session expired</h3>
            <p class="subtitle">The QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"error":return`
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${r?.errorMessage??"Failed to start authentication."}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;default:return""}}_qrFrameHtml(t,r){let n=$(t,440);return`
      <div class="qr-frame ${r?"scanned":""}${this.animated?" animated":""}">
        <div class="qr-image" role="img" aria-label="QR Code for authentication">${n}</div>
        <div class="qr-badge">${G}</div>
        ${r?'<div class="scanned-overlay"><span class="scanned-check">'+Qe+"</span></div>":""}
      </div>
    `}_mobilePendingBody(t,r){let n=t==="SCANNED";return`
      <h3>Sign in with QRAuth</h3>
      <p class="subtitle">Tap continue to verify on this device.</p>
      <button class="mobile-cta" id="mobile-cta" type="button">
        <span class="btn-icon">${G}</span>
        Continue with QRAuth
      </button>
      <div class="status-text ${n?"status-scanned":""}">
        ${n?"&#10003; Scanned &mdash; waiting for approval...":"Waiting for approval..."}
      </div>
      <div class="timer" id="timer">${r?.timerHtml??""}</div>
      <details class="alt-device">
        <summary>Use another device</summary>
        ${this._qrFrameHtml(r?.qrUrl??"",n)}
      </details>
      <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
    `}_sharedModalStyles(){return`
      /* Typography */
      h3 {
        font-size: 18px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 6px;
      }
      .subtitle {
        font-size: 13px;
        color: var(--_text-muted);
        margin: 0 0 20px;
        line-height: 1.5;
      }

      /* Close button */
      .close-btn {
        position: absolute;
        top: 12px;
        right: 14px;
        background: none;
        border: none;
        cursor: pointer;
        color: var(--_text-muted);
        font-size: 22px;
        line-height: 1;
        padding: 4px 6px;
        border-radius: 6px;
        transition: color 0.15s, background 0.15s;
        font-family: inherit;
      }
      .close-btn:hover { color: var(--_text); background: var(--_surface); }

      /* Brand icon in idle state */
      .state-header { padding: 8px 0 4px; }
      .brand-icon {
        width: 56px;
        height: 56px;
        background: var(--_btn-bg);
        border-radius: 14px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 14px;
        padding: 10px;
      }
      .brand-icon svg { width: 36px; height: 36px; }

      /* Loading state */
      .state-loading {
        padding: 32px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 40px;
        height: 40px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame */
      .qr-frame {
        display: inline-block;
        padding: 14px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 14px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame.scanned { border-color: var(--_success); }
      .qr-frame.animated { animation: qr-pulse 2s ease-in-out infinite; }
      @keyframes qr-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(0,167,111,0); }
        50% { box-shadow: 0 0 0 8px rgba(0,167,111,0.15); }
      }
      .qr-frame .qr-image { display: block; width: 220px; height: 220px; border-radius: 4px; overflow: hidden; }
      .qr-frame .qr-image svg { display: block; width: 100%; height: 100%; }
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 52px;
        height: 52px;
        background: #1b2a4a;
        border-radius: 10px;
        padding: 6px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .qr-badge svg { width: 100%; height: 100%; }

      /* Scanned overlay on QR */
      .scanned-overlay {
        position: absolute;
        inset: 0;
        background: rgba(0,167,111,0.08);
        border-radius: calc(var(--_radius) - 2px);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .scanned-check {
        width: 48px;
        height: 48px;
        background: var(--_success);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        opacity: 0;
        animation: pop-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.1s forwards;
      }
      .scanned-check svg { width: 28px; height: 28px; }
      @keyframes pop-in {
        from { transform: scale(0.5); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }

      /* Status text */
      .status-text {
        font-size: 13px;
        color: var(--_text-muted);
        min-height: 20px;
      }
      .status-scanned {
        color: var(--_success);
        font-weight: 600;
      }

      /* Timer */
      .timer {
        font-size: 12px;
        color: var(--_disabled);
        margin-top: 8px;
        font-variant-numeric: tabular-nums;
        min-height: 18px;
      }

      /* Success state */
      .state-approved {
        padding: 24px 0 12px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 64px;
        height: 64px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 16px;
      }
      .success-icon svg { width: 36px; height: 36px; }

      /* Denied / expired / error states */
      .state-denied, .state-expired, .state-error {
        padding: 20px 0 8px;
      }
      .error-icon, .expired-icon {
        font-size: 48px;
        margin-bottom: 12px;
        line-height: 1;
        display: block;
      }
      .state-denied .error-icon   { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon    { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 14px;
        padding: 9px 22px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Mobile-aware pending state: primary CTA + QR expander */
      .mobile-cta {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        width: 100%;
        padding: 14px 20px;
        background: var(--_btn-bg);
        color: #fff;
        border: none;
        border-radius: var(--_radius);
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        font-family: inherit;
        margin-bottom: 16px;
      }
      .mobile-cta:hover { background: var(--_btn-hover); }
      .mobile-cta .btn-icon { width: 20px; height: 20px; }

      details.alt-device {
        margin-top: 14px;
        text-align: left;
        border-top: 1px solid var(--_border);
        padding-top: 12px;
      }
      details.alt-device summary {
        cursor: pointer;
        font-size: 13px;
        color: var(--_text-muted);
        user-select: none;
        padding: 6px 0;
        text-align: center;
        list-style: none;
      }
      details.alt-device summary::-webkit-details-marker { display: none; }
      details.alt-device summary::before {
        content: '\u25B8 ';
        display: inline-block;
        transition: transform 0.2s;
      }
      details.alt-device[open] summary::before { transform: rotate(90deg); }
      details.alt-device > .qr-frame { margin-top: 10px; }

      /* Footer */
      .footer {
        margin-top: 18px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `}_bindButtonEvents(){this.shadow.getElementById("open-btn")?.addEventListener("click",()=>{this._openModal(),this._startAuth()});let r=this.shadow.getElementById("overlay");r?.addEventListener("click",n=>{n.target===r&&this._closeModal()}),this._bindModalButtons()}_bindInlineEvents(){this.shadow.getElementById("start-btn")?.addEventListener("click",()=>{this._startAuth()})}_bindModalButtons(){this.shadow.getElementById("close-btn")?.addEventListener("click",()=>this._closeModal()),this.shadow.getElementById("retry-btn")?.addEventListener("click",()=>this._retry()),this.shadow.getElementById("mobile-cta")?.addEventListener("click",()=>this._openApprovalPage())}_openApprovalPage(){if(!this._sessionToken)return;let t=`${this.baseUrl}/a/${this._sessionToken}`;window.open(t,"_blank","noopener")||(window.location.href=t)}_openModal(){this.shadow.getElementById("overlay")?.classList.remove("hidden"),this._updateBody(this._bodyForStatus("idle"))}_closeModal(){this.shadow.getElementById("overlay")?.classList.add("hidden"),this._clearTimers(),this._sessionId=null,this._sessionToken=null,this._codeVerifier=null,this._status="idle",this._expiresAt=null,this._currentQrUrl=null}async _startAuth(){this._status="loading",this._updateBody(this._bodyForStatus("loading"));try{this._codeVerifier=await this.generateCodeVerifier();let t=await this.computeCodeChallenge(this._codeVerifier),r={"Content-Type":"application/json","X-Client-Id":this.tenant},n={scopes:this.scopes.split(/\s+/).filter(Boolean),codeChallenge:t,codeChallengeMethod:"S256"};this.redirectUri&&(n.redirectUrl=this.redirectUri);let s=await fetch(`${this.baseUrl}/api/v1/auth-sessions`,{method:"POST",headers:r,body:JSON.stringify(n)});if(!s.ok){let a=await s.json().catch(()=>({message:"Failed to create session"}));throw new Error(a.message??"Failed to create session")}let o=await s.json();this._sessionId=o.sessionId,this._sessionToken=o.token||(o.qrUrl?o.qrUrl.split("/").pop()??null:null),this._expiresAt=new Date(o.expiresAt).getTime(),this._currentQrUrl=o.qrUrl??null,this._status="pending",this._updateBody(this._bodyForStatus("pending",{qrUrl:o.qrUrl})),this._bindModalButtons(),this._startCountdown(),this._beginPolling(o.sessionId)}catch(t){let r=t instanceof Error?t.message:"Unexpected error";this._status="error",this._updateBody(this._bodyForStatus("error",{errorMessage:r})),this._bindModalButtons(),this.emit("qrauth:error",{message:r})}}_retry(){if(this._clearTimers(),this._sessionId=null,this._sessionToken=null,this._codeVerifier=null,this._status="idle",this._expiresAt=null,this._currentQrUrl=null,this.display==="inline"){let t=this.shadow.getElementById("inline-body");t&&(t.innerHTML=this._inlineIdleContent(),this._bindInlineEvents())}else this._startAuth()}_beginPolling(t){let r="PENDING",n=2e3,s=5e3,o=0,a=20,l=async()=>{if(!this._sessionId)return;let d=`${this.baseUrl}/api/v1/auth-sessions/${t}`;this._codeVerifier&&(d+=`?code_verifier=${encodeURIComponent(this._codeVerifier)}`);try{let u=await(await fetch(d,{headers:{"X-Client-Id":this.tenant}})).json();if(o=0,n=2e3,u.status!==r&&(r=u.status,this._handleStatusChange(u.status,u),["APPROVED","DENIED","EXPIRED"].includes(u.status)))return;this._pollTimeout=setTimeout(l,n)}catch{if(o++,o>=a){this._handleStatusChange("EXPIRED",void 0);return}n=Math.min(n*1.5,s),this._pollTimeout=setTimeout(l,n)}};this._pollTimeout=setTimeout(l,n)}_handleStatusChange(t,r){switch(this._status=t,t){case"SCANNED":{this._updateBody(this._bodyForStatus("SCANNED",{qrUrl:this._currentQrUrl??"",timerHtml:this._formatTimer()})),this._bindModalButtons(),this.emit("qrauth:scanned",r);break}case"APPROVED":{this._clearTimers(),this._updateBody(this._bodyForStatus("APPROVED")),this._bindModalButtons(),this.emit("qrauth:authenticated",{sessionId:r?.sessionId,user:r?.user,signature:r?.signature});let n=this.onAuth;if(n){let s=window[n];typeof s=="function"&&s(r)}this.redirectUrl?setTimeout(()=>{window.location.href=this.redirectUrl},1500):this.display==="button"&&setTimeout(()=>this._closeModal(),2200);break}case"DENIED":this._clearTimers(),this._updateBody(this._bodyForStatus("DENIED")),this._bindModalButtons(),this.emit("qrauth:denied");break;case"EXPIRED":this._clearTimers(),this._status="EXPIRED",this._updateBody(this._bodyForStatus("EXPIRED")),this._bindModalButtons(),this.emit("qrauth:expired");break}}_startCountdown(){this._timerInterval=setInterval(()=>{let t=this.shadow.getElementById("timer");if(!t||!this._expiresAt)return;let r=Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3));t.textContent=r>0?this._formatTimer(r):"",r<=0&&(clearInterval(this._timerInterval),this._timerInterval=null,(this._status==="pending"||this._status==="SCANNED")&&this._handleStatusChange("EXPIRED",void 0))},1e3)}_formatTimer(t){let r=t??(this._expiresAt?Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3)):0),n=Math.floor(r/60),s=r%60;return`Expires in ${n}:${s<10?"0":""}${s}`}_updateBody(t){let r=this.display==="inline"?this.shadow.getElementById("inline-body"):this.shadow.getElementById("modal-body");r&&(r.innerHTML=t)}_clearTimers(){this._timerInterval&&(clearInterval(this._timerInterval),this._timerInterval=null),this._pollTimeout&&(clearTimeout(this._pollTimeout),this._pollTimeout=null)}};customElements.define("qrauth-login",J);var ut=`<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z"
        fill="none" stroke="#fff" stroke-width="5"/>
  <g fill="#fff" opacity="0.2">
    <rect x="52" y="40" width="18" height="18" rx="3"/>
    <rect x="78" y="40" width="18" height="18" rx="3"/>
    <rect x="130" y="40" width="18" height="18" rx="3"/>
    <rect x="52" y="66" width="18" height="18" rx="3"/>
    <rect x="104" y="66" width="18" height="18" rx="3"/>
    <rect x="78" y="92" width="18" height="18" rx="3"/>
    <rect x="130" y="92" width="18" height="18" rx="3"/>
    <rect x="52" y="118" width="18" height="18" rx="3"/>
    <rect x="104" y="118" width="18" height="18" rx="3"/>
  </g>
  <path d="M62 104 L88 134 L144 64"
        fill="none" stroke="#fff" stroke-width="15"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`,Xr=`<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="currentColor"/>
</svg>`,Gr=`<svg class="spinner" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2.5"
          stroke-dasharray="31.416" stroke-dashoffset="10" stroke-linecap="round"/>
</svg>`,W=class extends y{constructor(){super(...arguments);p(this,"_sessionId",null);p(this,"_claimUrl",null);p(this,"_status","idle");p(this,"_expiresAt",null);p(this,"_timerInterval",null);p(this,"_pollTimeout",null)}static get observedAttributes(){return[...super.observedAttributes,"scopes","ttl","max-uses","device-binding","display"]}get scopes(){return this.getAttribute("scopes")||"access"}get ttl(){return this.getAttribute("ttl")||"30m"}get maxUses(){return parseInt(this.getAttribute("max-uses")||"1",10)}get deviceBinding(){return this.hasAttribute("device-binding")}get display(){return this.getAttribute("display")||"inline"}get forceMode(){let t=this.getAttribute("force-mode");return t==="mobile"||t==="desktop"?t:"auto"}get mobileFallbackOnly(){return this.hasAttribute("mobile-fallback-only")}disconnectedCallback(){super.disconnectedCallback(),this._clearTimers()}render(){this.display==="button"?this._renderButton():this._renderInline()}_renderButton(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: inline-block; }

        .btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          user-select: none;
          line-height: 1.4;
          font-family: inherit;
        }
        .btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .btn:active:not(:disabled) { transform: translateY(0); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        /* Modal overlay */
        .overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.55);
          z-index: 99999;
          display: flex;
          align-items: center;
          justify-content: center;
          animation: fade-in 0.2s ease;
        }
        .overlay.hidden { display: none; }

        @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slide-up {
          from { transform: translateY(24px); opacity: 0; }
          to   { transform: translateY(0); opacity: 1; }
        }

        .modal {
          background: var(--_bg);
          border-radius: 16px;
          padding: 32px 28px 24px;
          max-width: 380px;
          width: 90vw;
          box-shadow: var(--_shadow);
          text-align: center;
          animation: slide-up 0.3s ease;
          position: relative;
        }

        ${this._sharedModalStyles()}
      </style>

      <button class="btn" id="open-btn" aria-label="Get access QR code">
        <span class="btn-icon">${ut}</span>
        Get Access QR
      </button>

      <div class="overlay hidden" id="overlay" role="dialog" aria-modal="true" aria-label="QRAuth ephemeral access">
        <div class="modal">
          ${this._modalContent()}
        </div>
      </div>
    `,this._bindButtonEvents()}_renderInline(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .inline-container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 28px 24px 20px;
          text-align: center;
          max-width: 360px;
          margin: 0 auto;
        }

        /* Idle state: show start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
        }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        ${this._sharedModalStyles()}
      </style>

      <div class="inline-container">
        <div id="inline-body">
          ${this._inlineIdleContent()}
        </div>
      </div>
    `,this._bindInlineEvents()}_inlineIdleContent(){return`
      <button class="start-btn" id="start-btn" aria-label="Get access QR code">
        <span class="btn-icon">${ut}</span>
        Get Access QR
      </button>
    `}_modalContent(){return`
      <button class="close-btn" id="close-btn" aria-label="Close">&times;</button>
      <div id="modal-body">
        ${this._bodyForStatus("idle")}
      </div>
    `}_bodyForStatus(t,r){switch(t){case"idle":return`
          <div class="state-header">
            <div class="brand-icon">${ut}</div>
            <h3>Ephemeral Access</h3>
            <p>Scan to claim temporary access</p>
          </div>
        `;case"loading":return`
          <div class="state-loading">
            <div class="spinner-wrap">${Gr}</div>
            <p class="status-text">Generating access QR...</p>
          </div>
        `;case"active":{let n=$(r?.claimUrl??"",440),s=r?.useCount??0,o=r?.maxUses??1,l=o>1?`<div class="use-badge">${s}/${o} claimed</div>`:"";return`
          <h3>Scan to Access</h3>
          <p class="subtitle">Present this QR code to gain entry</p>
          <div class="qr-frame">
            <div class="qr-image" role="img" aria-label="Ephemeral access QR code">${n}</div>
            <div class="qr-badge">${ut}</div>
          </div>
          ${l}
          <div class="timer" id="timer">${r?.timerHtml??""}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `}case"CLAIMED":return`
          <div class="state-claimed">
            <div class="success-icon">${Xr}</div>
            <h3>Access granted!</h3>
            <p class="subtitle">The QR code has been claimed successfully</p>
          </div>
        `;case"EXPIRED":return`
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Access expired</h3>
            <p class="subtitle">This QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Generate new QR</button>
          </div>
        `;case"REVOKED":return`
          <div class="state-revoked">
            <div class="error-icon">&#128683;</div>
            <h3>Access revoked</h3>
            <p class="subtitle">This ephemeral session has been revoked.</p>
          </div>
        `;case"error":return`
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${r?.errorMessage??"Failed to create ephemeral session."}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;default:return""}}_sharedModalStyles(){return`
      /* Typography */
      h3 {
        font-size: 18px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 6px;
      }
      .subtitle {
        font-size: 13px;
        color: var(--_text-muted);
        margin: 0 0 20px;
        line-height: 1.5;
      }

      /* Close button */
      .close-btn {
        position: absolute;
        top: 12px;
        right: 14px;
        background: none;
        border: none;
        cursor: pointer;
        color: var(--_text-muted);
        font-size: 22px;
        line-height: 1;
        padding: 4px 6px;
        border-radius: 6px;
        transition: color 0.15s, background 0.15s;
        font-family: inherit;
      }
      .close-btn:hover { color: var(--_text); background: var(--_surface); }

      /* Brand icon in idle state */
      .state-header { padding: 8px 0 4px; }
      .brand-icon {
        width: 56px;
        height: 56px;
        background: var(--_btn-bg);
        border-radius: 14px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 14px;
        padding: 10px;
      }
      .brand-icon svg { width: 36px; height: 36px; }

      /* Loading state */
      .state-loading {
        padding: 32px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 40px;
        height: 40px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame */
      .qr-frame {
        display: inline-block;
        padding: 14px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 14px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame .qr-image { display: block; width: 220px; height: 220px; border-radius: 4px; overflow: hidden; }
      .qr-frame .qr-image svg { display: block; width: 100%; height: 100%; }
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 52px;
        height: 52px;
        background: #1b2a4a;
        border-radius: 10px;
        padding: 6px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .qr-badge svg { width: 100%; height: 100%; }

      /* Multi-use badge */
      .use-badge {
        display: inline-block;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 20px;
        padding: 4px 12px;
        font-size: 12px;
        font-weight: 600;
        color: var(--_text-muted);
        margin-bottom: 8px;
      }

      /* Status text */
      .status-text {
        font-size: 13px;
        color: var(--_text-muted);
        min-height: 20px;
      }

      /* Timer */
      .timer {
        font-size: 12px;
        color: var(--_disabled);
        margin-top: 8px;
        font-variant-numeric: tabular-nums;
        min-height: 18px;
      }

      /* Claimed / success state */
      .state-claimed {
        padding: 24px 0 12px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 64px;
        height: 64px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 16px;
      }
      .success-icon svg { width: 36px; height: 36px; }

      /* Expired / revoked / error states */
      .state-expired, .state-revoked, .state-error {
        padding: 20px 0 8px;
      }
      .error-icon, .expired-icon {
        font-size: 48px;
        margin-bottom: 12px;
        line-height: 1;
        display: block;
      }
      .state-revoked .error-icon { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon    { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 14px;
        padding: 9px 22px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Footer */
      .footer {
        margin-top: 18px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `}_bindButtonEvents(){this.shadow.getElementById("open-btn")?.addEventListener("click",()=>{this._openModal(),this._startSession()});let r=this.shadow.getElementById("overlay");r?.addEventListener("click",n=>{n.target===r&&this._closeModal()}),this._bindModalButtons()}_bindInlineEvents(){this.shadow.getElementById("start-btn")?.addEventListener("click",()=>{this._startSession()})}_bindModalButtons(){this.shadow.getElementById("close-btn")?.addEventListener("click",()=>this._closeModal()),this.shadow.getElementById("retry-btn")?.addEventListener("click",()=>this._retry())}_openModal(){this.shadow.getElementById("overlay")?.classList.remove("hidden"),this._updateBody(this._bodyForStatus("idle"))}_closeModal(){this.shadow.getElementById("overlay")?.classList.add("hidden"),this._clearTimers(),this._sessionId=null,this._claimUrl=null,this._status="idle",this._expiresAt=null}async _startSession(){this._status="loading",this._updateBody(this._bodyForStatus("loading"));try{let t=await fetch(`${this.baseUrl}/api/v1/ephemeral`,{method:"POST",headers:{"Content-Type":"application/json","X-Client-Id":this.tenant},body:JSON.stringify({scopes:this.scopes.split(/\s+/).filter(Boolean),ttl:this.ttl,maxUses:this.maxUses,deviceBinding:this.deviceBinding})});if(!t.ok){let n=await t.json().catch(()=>({message:"Failed to create session"}));throw new Error(n.message??"Failed to create session")}let r=await t.json();this._sessionId=r.sessionId,this._claimUrl=r.claimUrl,this._expiresAt=new Date(r.expiresAt).getTime(),this._status="active",this._updateBody(this._bodyForStatus("active",{claimUrl:r.claimUrl,timerHtml:this._formatTimer(),useCount:0,maxUses:r.maxUses})),this._bindModalButtons(),this._startCountdown(),this._beginPolling(r.sessionId)}catch(t){let r=t instanceof Error?t.message:"Unexpected error";this._status="error",this._updateBody(this._bodyForStatus("error",{errorMessage:r})),this._bindModalButtons(),this.emit("qrauth:error",{message:r})}}_retry(){if(this._clearTimers(),this._sessionId=null,this._claimUrl=null,this._status="idle",this._expiresAt=null,this.display==="inline"){let t=this.shadow.getElementById("inline-body");t&&(t.innerHTML=this._inlineIdleContent(),this._bindInlineEvents())}else this._startSession()}_beginPolling(t){let r=2e3,n=5e3,s=0,o=20,a=async()=>{if(this._sessionId)try{let d=await(await fetch(`${this.baseUrl}/api/v1/ephemeral/${t}`,{headers:{"X-Client-Id":this.tenant}})).json();if(s=0,r=2e3,this._handleStatusChange(d.status,d),["CLAIMED","EXPIRED","REVOKED"].includes(d.status)){if(d.status==="CLAIMED"&&d.useCount<d.maxUses){this._updateBody(this._bodyForStatus("active",{claimUrl:this._claimUrl??void 0,timerHtml:this._formatTimer(),useCount:d.useCount,maxUses:d.maxUses})),this._bindModalButtons(),this._pollTimeout=setTimeout(a,r);return}return}this._pollTimeout=setTimeout(a,r)}catch{if(s++,s>=o){this._handleStatusChange("EXPIRED",void 0);return}r=Math.min(r*1.5,n),this._pollTimeout=setTimeout(a,r)}};this._pollTimeout=setTimeout(a,r)}_handleStatusChange(t,r){switch(t){case"CLAIMED":{this._clearTimers(),this._status="CLAIMED",this._updateBody(this._bodyForStatus("CLAIMED")),this._bindModalButtons(),this.emit("qrauth:claimed",{sessionId:r?.sessionId,status:r?.status,scopes:r?.scopes,metadata:r?.metadata,useCount:r?.useCount,maxUses:r?.maxUses}),this.display==="button"&&setTimeout(()=>this._closeModal(),2200);break}case"EXPIRED":this._clearTimers(),this._status="EXPIRED",this._updateBody(this._bodyForStatus("EXPIRED")),this._bindModalButtons(),this.emit("qrauth:expired");break;case"REVOKED":this._clearTimers(),this._status="REVOKED",this._updateBody(this._bodyForStatus("REVOKED")),this._bindModalButtons(),this.emit("qrauth:revoked");break}}_startCountdown(){this._timerInterval=setInterval(()=>{let t=this.shadow.getElementById("timer");if(!t||!this._expiresAt)return;let r=Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3));t.textContent=r>0?this._formatTimer(r):"",r<=0&&(clearInterval(this._timerInterval),this._timerInterval=null,this._status==="active"&&this._handleStatusChange("EXPIRED",void 0))},1e3)}_formatTimer(t){let r=t??(this._expiresAt?Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3)):0),n=Math.floor(r/60),s=r%60;return`Expires in ${n}:${s<10?"0":""}${s}`}_updateBody(t){let r=this.display==="inline"?this.shadow.getElementById("inline-body"):this.shadow.getElementById("modal-body");r&&(r.innerHTML=t)}_clearTimers(){this._timerInterval&&(clearInterval(this._timerInterval),this._timerInterval=null),this._pollTimeout&&(clearTimeout(this._pollTimeout),this._pollTimeout=null)}};customElements.define("qrauth-ephemeral",W);var ht=`<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z"
        fill="none" stroke="#fff" stroke-width="5"/>
  <g fill="#fff" opacity="0.2">
    <rect x="52" y="40" width="18" height="18" rx="3"/>
    <rect x="78" y="40" width="18" height="18" rx="3"/>
    <rect x="130" y="40" width="18" height="18" rx="3"/>
    <rect x="52" y="66" width="18" height="18" rx="3"/>
    <rect x="104" y="66" width="18" height="18" rx="3"/>
    <rect x="78" y="92" width="18" height="18" rx="3"/>
    <rect x="130" y="92" width="18" height="18" rx="3"/>
    <rect x="52" y="118" width="18" height="18" rx="3"/>
    <rect x="104" y="118" width="18" height="18" rx="3"/>
  </g>
  <path d="M62 104 L88 134 L144 64"
        fill="none" stroke="#fff" stroke-width="15"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`,He=`<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="currentColor"/>
</svg>`,Jr=`<svg class="spinner" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2.5"
          stroke-dasharray="31.416" stroke-dashoffset="10" stroke-linecap="round"/>
</svg>`,Z=class extends y{constructor(){super(...arguments);p(this,"_sessionId",null);p(this,"_sessionToken",null);p(this,"_codeVerifier",null);p(this,"_status","idle");p(this,"_expiresAt",null);p(this,"_currentQrUrl",null);p(this,"_timerInterval",null);p(this,"_pollTimeout",null)}static get observedAttributes(){return[...super.observedAttributes,"session-token","scopes","auto-start","redirect-uri"]}get sessionToken(){return this.getAttribute("session-token")}get scopes(){return this.getAttribute("scopes")||"identity"}get autoStart(){return this.hasAttribute("auto-start")}get redirectUri(){return this.getAttribute("redirect-uri")}get forceMode(){let t=this.getAttribute("force-mode");return t==="mobile"||t==="desktop"?t:"auto"}get mobileFallbackOnly(){return this.hasAttribute("mobile-fallback-only")}connectedCallback(){super.connectedCallback(),this.autoStart&&this._startAuth()}disconnectedCallback(){super.disconnectedCallback(),this._clearTimers()}render(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 24px 20px 18px;
          text-align: center;
          max-width: 320px;
          margin: 0 auto;
          box-shadow: 0 2px 12px rgba(0,0,0,0.06);
        }

        /* Step indicator */
        .step-label {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          color: var(--_primary);
          background: rgba(0,167,111,0.08);
          border-radius: 20px;
          padding: 4px 10px;
          margin-bottom: 14px;
        }
        .step-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: var(--_primary);
          flex-shrink: 0;
        }

        /* Idle start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 11px 22px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
          margin-top: 4px;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .start-btn:active:not(:disabled) { transform: translateY(0); }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 20px; height: 20px; flex-shrink: 0; }

        ${this._sharedStyles()}
      </style>

      <div class="container" role="region" aria-label="Second-factor authentication">
        <div id="body">
          ${this._bodyForStatus("idle")}
        </div>
      </div>
    `,this._bindBodyEvents()}_bodyForStatus(t,r){let n=`
      <div class="step-label">
        <span class="step-dot"></span>
        Step 2 of 2 &mdash; Verify identity
      </div>
    `;switch(t){case"idle":return`
          ${n}
          <div class="state-header">
            <div class="brand-icon">${ht}</div>
            <h3>Verify your identity</h3>
            <p class="subtitle">Scan the QR code with your phone to confirm it&apos;s you</p>
          </div>
          <button class="start-btn" id="start-btn" aria-label="Start 2FA verification">
            <span class="btn-icon">${ht}</span>
            Verify your identity
          </button>
        `;case"loading":return`
          ${n}
          <div class="state-loading">
            <div class="spinner-wrap">${Jr}</div>
            <p class="status-text">Generating QR code...</p>
          </div>
        `;case"pending":case"SCANNED":{if(this.isMobileLike())return this._mobilePendingBody(t,r,n);let s=t==="SCANNED";return`
          ${n}
          <h3>Scan to verify</h3>
          <p class="subtitle">Use your phone camera to complete verification</p>
          ${this._qrFrameHtml(r?.qrUrl??"",s)}
          <div class="status-text ${s?"status-scanned":""}">
            ${s?"&#10003; Scanned &mdash; waiting for approval...":"Waiting for scan..."}
          </div>
          <div class="timer" id="timer">${r?.timerHtml??""}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `}case"APPROVED":return`
          <div class="state-approved">
            <div class="success-icon">${He}</div>
            <h3>Identity verified!</h3>
            <p class="subtitle">Second factor confirmed</p>
          </div>
        `;case"DENIED":return`
          <div class="state-denied">
            <div class="error-icon">&#10007;</div>
            <h3>Verification denied</h3>
            <p class="subtitle">The request was declined on your device.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"EXPIRED":return`
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Session expired</h3>
            <p class="subtitle">The QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"error":return`
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${r?.errorMessage??"Failed to start verification."}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;default:return""}}_qrFrameHtml(t,r){let n=$(t,320);return`
      <div class="qr-frame ${r?"scanned":""}">
        <div class="qr-image" role="img" aria-label="QR Code for 2FA verification">${n}</div>
        <div class="qr-badge">${ht}</div>
        ${r?'<div class="scanned-overlay"><span class="scanned-check">'+He+"</span></div>":""}
      </div>
    `}_mobilePendingBody(t,r,n=""){let s=t==="SCANNED";return`
      ${n}
      <h3>Verify your identity</h3>
      <p class="subtitle">Tap continue to verify on this device.</p>
      <button class="mobile-cta" id="mobile-cta" type="button">
        <span class="btn-icon">${ht}</span>
        Continue with QRAuth
      </button>
      <div class="status-text ${s?"status-scanned":""}">
        ${s?"&#10003; Scanned &mdash; waiting for approval...":"Waiting for approval..."}
      </div>
      <div class="timer" id="timer">${r?.timerHtml??""}</div>
      <details class="alt-device">
        <summary>Use another device</summary>
        ${this._qrFrameHtml(r?.qrUrl??"",s)}
      </details>
      <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
    `}_sharedStyles(){return`
      /* Typography */
      h3 {
        font-size: 16px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 5px;
      }
      .subtitle {
        font-size: 12px;
        color: var(--_text-muted);
        margin: 0 0 16px;
        line-height: 1.5;
      }

      /* Brand icon in idle state */
      .state-header { padding: 4px 0 2px; }
      .brand-icon {
        width: 48px;
        height: 48px;
        background: var(--_btn-bg);
        border-radius: 12px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 12px;
        padding: 8px;
      }
      .brand-icon svg { width: 32px; height: 32px; }

      /* Loading state */
      .state-loading {
        padding: 24px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 14px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 36px;
        height: 36px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame \u2014 compact 160x160 */
      .qr-frame {
        display: inline-block;
        padding: 10px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 12px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame.scanned { border-color: var(--_success); }
      .qr-frame .qr-image { display: block; width: 160px; height: 160px; border-radius: 4px; overflow: hidden; }
      .qr-frame .qr-image svg { display: block; width: 100%; height: 100%; }

      /* Smaller badge for compact QR */
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 40px;
        height: 40px;
        background: #1b2a4a;
        border-radius: 8px;
        padding: 5px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .qr-badge svg { width: 100%; height: 100%; }

      /* Scanned overlay on QR */
      .scanned-overlay {
        position: absolute;
        inset: 0;
        background: rgba(0,167,111,0.08);
        border-radius: calc(var(--_radius) - 2px);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .scanned-check {
        width: 40px;
        height: 40px;
        background: var(--_success);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        opacity: 0;
        animation: pop-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.1s forwards;
      }
      .scanned-check svg { width: 22px; height: 22px; }
      @keyframes pop-in {
        from { transform: scale(0.5); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }

      /* Status text */
      .status-text {
        font-size: 12px;
        color: var(--_text-muted);
        min-height: 18px;
      }
      .status-scanned {
        color: var(--_success);
        font-weight: 600;
      }

      /* Timer */
      .timer {
        font-size: 11px;
        color: var(--_disabled);
        margin-top: 6px;
        font-variant-numeric: tabular-nums;
        min-height: 16px;
      }

      /* Success state */
      .state-approved {
        padding: 16px 0 8px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 56px;
        height: 56px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 14px;
      }
      .success-icon svg { width: 30px; height: 30px; }

      /* Denied / expired / error states */
      .state-denied, .state-expired, .state-error {
        padding: 16px 0 6px;
      }
      .error-icon, .expired-icon {
        font-size: 40px;
        margin-bottom: 10px;
        line-height: 1;
        display: block;
      }
      .state-denied .error-icon    { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon     { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 12px;
        padding: 8px 20px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Mobile-aware pending state: primary CTA + QR expander */
      .mobile-cta {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        width: 100%;
        padding: 12px 18px;
        background: var(--_btn-bg);
        color: #fff;
        border: none;
        border-radius: var(--_radius);
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        font-family: inherit;
        margin-bottom: 12px;
      }
      .mobile-cta:hover { background: var(--_btn-hover); }
      .mobile-cta .btn-icon { width: 18px; height: 18px; }

      details.alt-device {
        margin-top: 12px;
        text-align: left;
        border-top: 1px solid var(--_border);
        padding-top: 10px;
      }
      details.alt-device summary {
        cursor: pointer;
        font-size: 12px;
        color: var(--_text-muted);
        user-select: none;
        padding: 4px 0;
        text-align: center;
        list-style: none;
      }
      details.alt-device summary::-webkit-details-marker { display: none; }
      details.alt-device summary::before {
        content: '\u25B8 ';
        display: inline-block;
        transition: transform 0.2s;
      }
      details.alt-device[open] summary::before { transform: rotate(90deg); }
      details.alt-device > .qr-frame { margin-top: 8px; }

      /* Footer */
      .footer {
        margin-top: 14px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `}_bindBodyEvents(){this.shadow.getElementById("start-btn")?.addEventListener("click",()=>this._startAuth()),this.shadow.getElementById("retry-btn")?.addEventListener("click",()=>this._retry()),this.shadow.getElementById("mobile-cta")?.addEventListener("click",()=>this._openApprovalPage())}_openApprovalPage(){if(!this._sessionToken)return;let t=`${this.baseUrl}/a/${this._sessionToken}`;window.open(t,"_blank","noopener")||(window.location.href=t)}async _startAuth(){this._status="loading",this._updateBody(this._bodyForStatus("loading"));try{this._codeVerifier=await this.generateCodeVerifier();let t=await this.computeCodeChallenge(this._codeVerifier),r={"Content-Type":"application/json","X-Client-Id":this.tenant},n={scopes:this.scopes.split(/\s+/).filter(Boolean),codeChallenge:t,codeChallengeMethod:"S256"};this.redirectUri&&(n.redirectUrl=this.redirectUri);let s=await fetch(`${this.baseUrl}/api/v1/auth-sessions`,{method:"POST",headers:r,body:JSON.stringify(n)});if(!s.ok){let a=await s.json().catch(()=>({message:"Failed to create session"}));throw new Error(a.message??"Failed to create session")}let o=await s.json();this._sessionId=o.sessionId,this._sessionToken=o.token||(o.qrUrl?o.qrUrl.split("/").pop()??null:null),this._expiresAt=new Date(o.expiresAt).getTime(),this._currentQrUrl=o.qrUrl??null,this._status="pending",this._updateBody(this._bodyForStatus("pending",{qrUrl:o.qrUrl})),this._bindBodyEvents(),this._startCountdown(),this._beginPolling(o.sessionId)}catch(t){let r=t instanceof Error?t.message:"Unexpected error";this._status="error",this._updateBody(this._bodyForStatus("error",{errorMessage:r})),this._bindBodyEvents(),this.emit("qrauth:error",{message:r})}}_retry(){this._clearTimers(),this._sessionId=null,this._sessionToken=null,this._codeVerifier=null,this._status="idle",this._expiresAt=null,this._currentQrUrl=null,this._updateBody(this._bodyForStatus("idle")),this._bindBodyEvents()}_beginPolling(t){let r="PENDING",n=2e3,s=5e3,o=0,a=20,l=async()=>{if(!this._sessionId)return;let d=`${this.baseUrl}/api/v1/auth-sessions/${t}`;this._codeVerifier&&(d+=`?code_verifier=${encodeURIComponent(this._codeVerifier)}`);try{let u=await(await fetch(d,{headers:{"X-Client-Id":this.tenant}})).json();if(o=0,n=2e3,u.status!==r&&(r=u.status,this._handleStatusChange(u.status,u),["APPROVED","DENIED","EXPIRED"].includes(u.status)))return;this._pollTimeout=setTimeout(l,n)}catch{if(o++,o>=a){this._handleStatusChange("EXPIRED",void 0);return}n=Math.min(n*1.5,s),this._pollTimeout=setTimeout(l,n)}};this._pollTimeout=setTimeout(l,n)}_handleStatusChange(t,r){switch(this._status=t,t){case"SCANNED":{this._updateBody(this._bodyForStatus("SCANNED",{qrUrl:this._currentQrUrl??"",timerHtml:this._formatTimer()})),this._bindBodyEvents();break}case"APPROVED":{this._clearTimers(),this._updateBody(this._bodyForStatus("APPROVED")),this.emit("qrauth:verified",{sessionId:r?.sessionId,user:r?.user,signature:r?.signature});break}case"DENIED":this._clearTimers(),this._updateBody(this._bodyForStatus("DENIED")),this._bindBodyEvents(),this.emit("qrauth:denied");break;case"EXPIRED":this._clearTimers(),this._status="EXPIRED",this._updateBody(this._bodyForStatus("EXPIRED")),this._bindBodyEvents(),this.emit("qrauth:expired");break}}_startCountdown(){this._timerInterval=setInterval(()=>{let t=this.shadow.getElementById("timer");if(!t||!this._expiresAt)return;let r=Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3));t.textContent=r>0?this._formatTimer(r):"",r<=0&&(clearInterval(this._timerInterval),this._timerInterval=null,(this._status==="pending"||this._status==="SCANNED")&&this._handleStatusChange("EXPIRED",void 0))},1e3)}_formatTimer(t){let r=t??(this._expiresAt?Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3)):0),n=Math.floor(r/60),s=r%60;return`Expires in ${n}:${s<10?"0":""}${s}`}_updateBody(t){let r=this.shadow.getElementById("body");r&&(r.innerHTML=t)}_clearTimers(){this._timerInterval&&(clearInterval(this._timerInterval),this._timerInterval=null),this._pollTimeout&&(clearTimeout(this._pollTimeout),this._pollTimeout=null)}};customElements.define("qrauth-2fa",Z);return tr(Wr);})();
//# sourceMappingURL=qrauth-components.js.map
