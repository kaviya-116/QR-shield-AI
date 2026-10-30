(()=>{"use strict";
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const h=(t,a={},...k)=>{const e=document.createElement(t);for(const[n,v]of Object.entries(a)){if(n==="class")e.className=v;else if(n.startsWith("on"))e.addEventListener(n.slice(2),v);else e.setAttribute(n,v)}e.append(...k.filter(x=>x!=null));return e};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const S={url:null,report:null,stream:null,raf:0};
const CAT={green:["GREEN — NO KNOWN THREAT DETECTED","No known threat was identified by the available checks. This does not guarantee safety."],
amber:["AMBER — SUSPICIOUS","One or more suspicious indicators require further review."],
red:["RED — KNOWN THREAT DETECTED","A trusted threat-intelligence source reports a known malicious destination."],
gray:["GRAY — UNABLE TO VERIFY","The service failed, returned insufficient data, or the URL could not be reliably evaluated."]};
const STEPS={green:["Treat the link like any unknown link: check the domain before entering personal data.","If the QR sat on a sticker, make sure it is not pasted over another code."],
amber:["Do not enter passwords, OTPs or payment details on this site.","Confirm the destination with the person or business that gave you the code."],
red:["Do not visit this destination.","If you already did, change passwords you entered and contact your bank if payment data was shared."],
gray:["Treat this link as unverified.","Try again later, or verify the destination through another channel."]};

/* navigation */
function show(v){$$(".view").forEach(s=>s.classList.toggle("on",s.id==="v-"+v));$$("#nav button[data-view]").forEach(b=>b.classList.toggle("on",b.dataset.view===v&&!b.classList.contains("cta")));$("#main").focus({preventScroll:true});scrollTo(0,0);if(v==="history")renderHistory();if(v==="home")renderRecent();if(v==="challenge"&&!Q.started)quiz()}
document.addEventListener("click",e=>{const b=e.target.closest("[data-view]");if(b){e.preventDefault();show(b.dataset.view)}});

/* scanner */
const st=(m,c="")=>{const e=$("#status");e.textContent=m;e.className="status "+c};
function decodeCanvas(c){const x=c.getContext("2d",{willReadFrequently:true});const d=x.getImageData(0,0,c.width,c.height);return jsQR(d.data,c.width,c.height,{inversionAttempts:"attemptBoth"})}
function handleText(t){$("#decoded").textContent=t;if(/^https?:\/\//i.test(t.trim())){S.url=t.trim();$("#analyze").disabled=false;st("QR code decoded. Review the link, then press Analyze. It will not be opened.","ok")}
else{S.url=null;$("#analyze").disabled=true;const m=t.match(/^([a-z][a-z0-9+.-]*):/i);st(m?`This QR holds non-web content (${m[1]}:). It is shown as text only and never opened.`:"This QR holds plain text, not a link. Nothing was opened.","err")}}
const LIBS=["https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js","https://cdnjs.cloudflare.com/ajax/libs/jsQR/1.4.0/jsQR.min.js"];
function loadLib(i=0){return new Promise(res=>{if(typeof jsQR!=="undefined"||i>=LIBS.length)return res(typeof jsQR!=="undefined");const s=document.createElement("script");s.src=LIBS[i];s.onload=()=>res(true);s.onerror=()=>{s.remove();loadLib(i+1).then(res)};document.head.append(s)})}
async function needLib(){if(typeof jsQR!=="undefined")return false;st("Loading QR decoder…");if(await loadLib()){st("");return false}st("The QR decoder (jsQR) could not be loaded. Connect to the internet, or save jsQR.js into static/vendor/ (see README).","err");return true}
$("#file").addEventListener("change",async e=>{const f=e.target.files[0];if(!f||await needLib())return;
if(!["image/png","image/jpeg"].includes(f.type))return st("Unsupported file. Choose a PNG or JPG image.","err");
if(f.size>5e6)return st("Image is larger than 5 MB. Choose a smaller file.","err");
st("Decoding…");const url=URL.createObjectURL(f),img=$("#preview");
img.onload=()=>{const k=Math.min(1,1600/Math.max(img.naturalWidth,img.naturalHeight)),c=document.createElement("canvas");c.width=img.naturalWidth*k|0;c.height=img.naturalHeight*k|0;c.getContext("2d").drawImage(img,0,0,c.width,c.height);
img.hidden=false;$("#empty").hidden=true;const r=decodeCanvas(c);r?handleText(r.data):(S.url=null,$("#analyze").disabled=true,$("#decoded").textContent="No QR code found.",st("No QR code found in this image. Try a sharper, well-lit, cropped picture.","err"));URL.revokeObjectURL(url)};
img.onerror=()=>st("This file could not be read as an image.","err");img.src=url});
async function camStart(){if(await needLib())return;if(!navigator.mediaDevices?.getUserMedia)return st("Camera is not supported here. Upload an image instead.","err");
try{S.stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}})}catch{return st("Camera permission was denied or no camera was found. Upload an image instead.","err")}
const v=$("#video");v.srcObject=S.stream;v.hidden=false;$("#preview").hidden=true;$("#empty").hidden=true;await v.play();$("#cam-start").disabled=true;$("#cam-stop").disabled=false;st("Scanning… hold the code steady.");
const c=document.createElement("canvas");const tick=()=>{if(!S.stream)return;if(v.readyState>=2&&v.videoWidth){c.width=v.videoWidth;c.height=v.videoHeight;c.getContext("2d",{willReadFrequently:true}).drawImage(v,0,0);const r=decodeCanvas(c);if(r){camStop();handleText(r.data);return}}S.raf=requestAnimationFrame(tick)};tick()}
function camStop(){cancelAnimationFrame(S.raf);S.stream?.getTracks().forEach(t=>t.stop());S.stream=null;$("#video").hidden=true;$("#cam-start").disabled=false;$("#cam-stop").disabled=true}
$("#cam-start").onclick=camStart;$("#cam-stop").onclick=()=>{camStop();st("Camera stopped.")};
$("#manual-go").onclick=()=>{const v=$("#manual").value.trim();v?handleText(v):st("Paste a link first.","err")};
$("#reset").onclick=()=>{camStop();S.url=null;$("#file").value="";$("#manual").value="";$("#preview").hidden=true;$("#empty").hidden=false;$("#decoded").textContent="Nothing decoded yet.";$("#analyze").disabled=true;st("")};
$("#home-upload").onclick=()=>{show("scan");$("#file").click()};
addEventListener("pagehide",camStop);

/* investigation */
const STAGES=["QR code decoded","Destination extracted","URL structure analyzed","Context mismatch evaluated","Threat intelligence checked","Risk report generated"];
function stage(i,state,msg){const li=$("#stages").children[i];li.className=state;li.children[0].textContent={done:"✓",error:"!",demo:"~",run:""}[state]||"";li.children[1].lastChild.textContent=msg}
function resetStages(){const o=$("#stages");o.replaceChildren(...STAGES.map(t=>h("li",{},h("span",{class:"ic"}),h("div",{},h("b",{},t),h("p",{},"Waiting…")))))}
$("#analyze").onclick=async()=>{if(!S.url)return;show("investigate");resetStages();
stage(0,"done","Decoded locally in your browser.");await sleep(250);
let host=null;try{host=new URL(S.url).hostname;stage(1,"done","Destination host: "+host)}catch{stage(1,"error","Could not parse a hostname.")}
stage(2,"run","Analyzing URL structure…");let r;
try{const res=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:S.url,purpose:$("#purpose").value,expected_domain:$("#expected").value})});
if(!res.ok)throw new Error((await res.json().catch(()=>({}))).error||res.statusText);r=await res.json()}
catch(e){r={ok:false,error:"Analysis server unreachable: "+e.message,host,indicators:[],context:[],score:0,category:"gray",sources:["none"],factors:[],intel:{source:"none",status:"error",detail:"Not checked: the backend did not respond."}};
stage(2,"error",r.error);for(let i=3;i<5;i++)stage(i,"error","Not performed.")}
if(r.ok){stage(2,"done",`${r.indicators.length} indicator(s) found, score ${r.score}/100.`);await sleep(250);
stage(3,"done",r.context.length?`${r.context.length} context mismatch signal(s).`:"No context mismatch found for the chosen purpose.");await sleep(250);
const i=r.intel;stage(4,i.status==="error"?"error":i.source==="demo"?"demo":"done",(i.source==="demo"?"DEMO MODE. ":"")+i.detail)}
else if(!r.indicators.length&&r.error&&!r.error.startsWith("Analysis server")){stage(2,"error",r.error);stage(3,"error","Skipped.");stage(4,"error","Skipped.")}
await sleep(250);stage(5,"done","Report ready.");S.report={...r,fullUrl:S.url,purposeLabel:$("#purpose").selectedOptions[0].text};saveHistory(S.report);renderReport(S.report);await sleep(400);show("report")};

/* report */
function renderReport(r){const c=r.category,box=$("#report"),[t,d]=CAT[c];box.replaceChildren();box.className=c;
box.append(h("div",{class:"banner"},h("h3",{},t),h("p",{},d)),
h("div",{class:"card"},h("b",{},"Indicator score: "+r.score+" / 100"),h("div",{class:"meter","aria-hidden":"true"},h("div")),h("p",{class:"muted"},"A transparent sum of the rules below. It is not a probability of attack.")));
$(".meter div",box).style.width=r.score+"%";
const tbl=h("table",{},h("tr",{},h("th",{},"Factor"),h("th",{},"Points"),h("th",{},"Why it matters")),...r.indicators.map(i=>h("tr",{},h("td",{},i.label),h("td",{},"+"+i.weight),h("td",{},i.detail))));
box.append(h("div",{class:"card"},h("h3",{},"Link"),h("pre",{class:"code"},r.fullUrl),h("p",{},"Hostname: ",h("b",{},r.host||"unavailable")),h("div",{class:"chips"},...r.sources.map(s=>h("span",{},"Source: "+s)),h("span",{},"Purpose: "+r.purposeLabel)),r.error?h("p",{class:"status err"},r.error):null,r.https_note?h("p",{class:"muted"},r.https_note):null));
box.append(h("div",{class:"card"},h("h3",{},"Security checks"),r.indicators.length?tbl:h("p",{},r.ok?"No local indicators triggered.":"Local checks could not run.")));
box.append(h("div",{class:"card"},h("h3",{},"Context check ",h("span",{class:"tag"},r.purposeLabel)),r.context.length?h("ul",{},...r.context.map(x=>h("li",{},x))):h("p",{},"No mismatch with the stated purpose. A mismatch would be a warning signal, not proof of malice.")));
const i=r.intel;box.append(h("div",{class:"card"},h("h3",{},"Threat intelligence ",i.source==="demo"?h("span",{class:"tag"},"DEMO MODE"):null),h("p",{},i.detail),h("p",{class:"muted"},"Source: "+i.source+". A missing report is never treated as proof of safety.")));
box.append(h("div",{class:"card"},h("h3",{},"Recommended next steps"),h("ul",{},...STEPS[c].map(x=>h("li",{},x)))));
box.append(h("div",{class:"row"},h("button",{class:"btn",onclick:()=>{show("redirects");$("#trace").click()}},"Investigate redirects"),r.ok?h("button",{class:"btn "+(c==="red"?"danger":"primary"),onclick:()=>warning(r)},"Review before visiting"):null,h("button",{class:"btn",onclick:()=>show("scan")},"Scan another code")))}

/* pre-visit protection */
function warning(r){let u;try{u=new URL(r.fullUrl)}catch{return}
if(!["http:","https:"].includes(u.protocol)){st("Blocked: unsafe protocol.","err");return}
const c=r.category,w=$("#warn");w.className="card warn "+c;w.replaceChildren(h("div",{class:"big","aria-hidden":"true"},c==="green"?"◈":"⚠"),h("h2",{},CAT[c][0]),h("p",{},CAT[c][1]),h("p",{},"Destination: ",h("b",{},u.hostname)),
r.indicators.length?h("ul",{},...r.indicators.map(i=>h("li",{},i.label))):null);
const go=h("button",{class:"btn primary",onclick:()=>show("scan")},"Go back to safety");let ok=null,cont=h("button",{class:"btn"+(c==="red"?" danger":""),onclick:()=>{if(ok&&!ok.checked)return;open(u.href,"_blank","noopener,noreferrer")}},c==="red"?"I accept the risk and continue":"Continue anyway");
if(c==="red"){ok=h("input",{type:"checkbox",id:"ack",style:"width:auto"});cont.disabled=true;ok.onchange=()=>cont.disabled=!ok.checked;w.append(h("p",{class:"status err"},"This destination is reported as malicious. Strongly discouraged."),h("label",{for:"ack"},ok," I understand this site is reported as malicious."))}
w.append(h("div",{class:"row",style:"justify-content:center"},go,cont));show("warning")}

/* redirects */
$("#trace").onclick=async()=>{const n=$("#trace-note"),ch=$("#chain");$("#hop").hidden=true;ch.replaceChildren();if(!S.report?.ok){n.textContent="Scan and analyze a link first.";return}
n.textContent="Tracing…";try{const res=await fetch("/api/redirects",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:S.report.fullUrl})});const d=await res.json();if(!res.ok)throw new Error(d.error);
n.textContent=(d.mode==="demo"?"[DEMO MODE] ":"")+d.note;
d.hops.forEach((p,i)=>{if(i)ch.append(h("span",{class:"arrow","aria-hidden":"true"},"→"));
const b=h("button",{class:"node "+(p.flag?"flag ":"")+(p.state==="blocked"?"blocked":""),"aria-pressed":"false",onclick:()=>{$$(".node").forEach(x=>x.setAttribute("aria-pressed","false"));b.setAttribute("aria-pressed","true");const x=$("#hop");x.hidden=false;x.replaceChildren(h("h3",{},p.host),h("p",{},"Step "+(i+1)+" · "+p.state+(p.demo?" · SIMULATED":"")),h("p",{},p.note),h("p",{class:"muted"},"Registered domain: "+p.registered),p.flag?h("p",{class:"status err"},p.flag):null)}},h("b",{},p.host),h("br"),h("small",{},p.state+(p.demo?" (demo)":"")));ch.append(b)})}
catch(e){n.textContent="Could not trace redirects: "+e.message}};

/* history */
const HK="qrshield.history.v1",load=()=>{try{return JSON.parse(localStorage.getItem(HK))||[]}catch{return[]}};
function saveHistory(r){try{const a=load();a.unshift({t:new Date().toISOString(),purpose:r.purposeLabel,host:r.host||"unavailable",cat:r.category,src:r.sources.join(" + "),score:r.score,why:r.indicators.map(i=>i.label)});localStorage.setItem(HK,JSON.stringify(a.slice(0,100)))}catch{}}
function renderHistory(){const q=$("#hsearch").value.toLowerCase(),f=$("#hfilter").value,a=load().filter(x=>(!f||x.cat===f)&&x.host.toLowerCase().includes(q)),l=$("#hlist");
l.replaceChildren(...(a.length?a.map(x=>h("details",{class:x.cat},h("summary",{},`${new Date(x.t).toLocaleString()} · ${x.host} · ${x.cat.toUpperCase()}`),h("p",{},`Purpose: ${x.purpose}. Source: ${x.src}. Score ${x.score}/100.`),h("ul",{},...(x.why.length?x.why:["No indicators"]).map(w=>h("li",{},w))))):[h("p",{class:"empty"},"No scans yet. Scan a QR code and it will appear here.")]))}
$("#hsearch").oninput=renderHistory;$("#hfilter").onchange=renderHistory;$("#hclear").onclick=()=>{if(confirm("Clear all scan history from this browser?")){try{localStorage.removeItem(HK)}catch{}renderHistory()}};
function renderRecent(){const a=load().slice(0,4),ul=$("#recent");ul.replaceChildren(...(a.length?a.map(x=>h("li",{},h("span",{},x.host),h("b",{class:x.cat},x.cat.toUpperCase()))):[["pay.example-demo.test","green"],["bit.ly/demo","amber"],["demo-threat.test","red"]].map(([n,c])=>h("li",{},h("span",{},n+" "),h("span",{class:"tag"},"DEMO DATA")))))}

/* challenge */
const BANK=[["You scan a parking-meter QR code. Which link is the red flag?",["https://city-parking.example.org/pay","https://city-parking.example.org.pay-now.example.top/","https://www.example.org/parking"],1,"The real registered domain is the part just before the last dot: here it is example.top, not example.org."],
["A flyer QR for a concert leads to a form asking for your card PIN. What do you do?",["Fill it in, it is for tickets","Stop: events do not need your PIN","Enter a fake PIN to see what happens"],1,"Never enter PINs or OTPs on a page reached from an unknown QR code."],
["Which hostname uses a look-alike trick?",["xn--pypal-4ve.example","paypal.example","pay.example"],0,"xn-- marks an internationalized domain. Look-alike letters can imitate real brands."],
["A sticker QR on a shop counter uses a link shortener. Best move?",["Open it, shortened links are normal","Ask staff and check where it really goes first","Share it with friends"],1,"Shorteners hide the destination. A sticker may have been pasted over the original code."],
["Which link is most suspicious?",["https://login.example.org/","https://example.org@192.0.2.9/login","https://example.org/login"],1,"Text before @ is ignored for the destination, and the real host here is a bare IP address."],
["Does HTTPS mean a site is safe?",["Yes, always","No, it only encrypts the connection","Only for banks"],1,"Scam sites can have valid HTTPS certificates too."]];
const Q={started:false,i:0,pts:0};
function quiz(){Q.started=true;const b=$("#quiz");if(Q.i>=BANK.length){const bd=Q.pts>=60?"Shield Master":Q.pts>=40?"Sharp Eye":"Rookie Scanner";b.replaceChildren(h("h3",{},"Challenge complete"),h("p",{},`Score: ${Q.pts} / ${BANK.length*10}`),h("p",{},h("span",{class:"tag"},"Badge: "+bd)),h("button",{class:"btn primary",onclick:()=>{Q.i=0;Q.pts=0;quiz()}},"Try again"));return}
const [q,o,a,why]=BANK[Q.i],fb=h("div",{"aria-live":"polite"});
b.replaceChildren(h("p",{class:"muted"},`Question ${Q.i+1} of ${BANK.length} · ${Q.pts} points`),h("div",{class:"meter","aria-hidden":"true"},h("div",{style:`width:${Q.i/BANK.length*100}%`})),h("h3",{},q),...o.map((t,k)=>{const bt=h("button",{class:"btn opt",onclick:()=>{$$(".opt",b).forEach((x,j)=>{x.disabled=true;x.classList.add(j===a?"good":j===k?"bad":"x")});if(k===a)Q.pts+=10;fb.replaceChildren(h("p",{class:"status "+(k===a?"ok":"err")},(k===a?"Correct. ":"Not quite. ")+why),h("button",{class:"btn primary",onclick:()=>{Q.i++;quiz()}},Q.i+1<BANK.length?"Next question":"See results"))}},t);return bt}),fb)}

/* boot */
fetch("/api/status").then(r=>r.json()).then(s=>{$("#mode").textContent=(s.threat_intel==="demo"?"Threat intel: DEMO MODE":"Threat intel: VirusTotal")+" · Redirects: "+(s.live_redirects?"live":"demo")}).catch(()=>{$("#mode").textContent="Backend offline"});
show("home");
})();
