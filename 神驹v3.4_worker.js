


/**

示例节点路径：

直连模式（只使用密钥，默认走直连 + 兜底反代策略。）
/my-key=abc

带 SOCKS5 代理（只使用密钥，默认走直连 + s5指定的节点 +兜底反代策略。）
/my-key=abc/s5=user:pass@1.2.3.4:1080/

带自定义反代 IP（只使用密钥，默认走直连 +pyip 指定的节点+兜底反代策略。）
/my-key=abc/pyip=5.6.7.8:443/



带多个参数组合
/my-key=abc/s5=user:pass@1.2.3.4:1080/pyip=5.6.7.8:443/


*/





// ===================================================================================
//
//      “泰坦神驹”核心引擎 v3.4 — ReactionMax (反应极限版)
//       
// ===================================================================================

import { connect } from 'cloudflare:sockets';

// ==================== 1. 全局配置 ====================
const CONFIG = {
    密钥: "abc", // 务必修改
    默认兜底反代: "ProxyIP.US.CMLiussss.net:443",
    
    // 策略开关
    启用普通反代: true,
    启用S5: true,
    启用全局S5: false,
    S5账号列表: ["user:pass@host:port"],
    强制S5名单: ["ip.sb", "ip125.com", "test.org"],

    // 运行参数
    首次数据包超时: 5000,
    连接停滞超时: 8000,
    最大停滞次数: 12,
    最大重连次数: 24,
    会话缓存TTL: 3 * 60 * 1000,

    // [v3.4] 健壮性参数 (在控制循环中使用)
    主动心跳间隔: 10000, 
    控制循环轮询间隔: 500, // ms
    吞吐量监测间隔: 5000, 
    吞吐量阈值_好: 500,
    吞吐量阈值_差: 50,
};

// ==================== 2. 生产级特性 (与v3.2相同) ====================
class Telemetry { /* ...内容与v3.2相同... */ push(e,d={}){console.log(JSON.stringify({event:e,...d,ts:new Date().toISOString()}))}}
const telemetry = new Telemetry();
class SessionCache { /* ...内容与v3.2相同... */ constructor(){this._map=new Map}set(k){this._map.set(k,Date.now())}has(k){const t=this._map.get(k);if(!t)return!1;if(Date.now()-t>CONFIG.会话缓存TTL){this._map.delete(k);return!1}return!0}}
const sessionCache = new SessionCache();

// ==================== 3. 核心辅助函数 (与v3.2相同) ====================
function websocketToStreams(ws) { /* ...内容与v3.2相同... */ const r=new ReadableStream({start(c){ws.addEventListener("message",e=>{if(e.data instanceof ArrayBuffer)c.enqueue(new Uint8Array(e.data))});ws.addEventListener("close",()=>{try{c.close()}catch{}});ws.addEventListener("error",e=>{try{c.error(e)}catch{}})}});const w=new WritableStream({write(c){if(ws.readyState===WebSocket.OPEN)ws.send(c)},close(){if(ws.readyState===WebSocket.OPEN)ws.close(1000)},abort(r){ws.close(1001,r?.message)}});return{readable:r,writable:w} }
function parsePathParams(pathname) { /* ...内容与v3.2相同... */ const p={};for(const t of pathname.split('/').filter(Boolean)){const i=t.indexOf('=');if(i===-1)continue;const k=t.slice(0,i),v=t.slice(i+1);if(k)p[k]=decodeURIComponent(v)}return p }
function parseHostPort(str, defaultPort) { /* ...内容与v3.2相同... */ if(!str)return[null,defaultPort];str=str.trim();const v6=str.match(/^\[([^\]]+)\](?::(\d+))?$/);if(v6)return[`[${v6[1]}]`,v6[2]?Number(v6[2]):defaultPort];const c=str.lastIndexOf(":");if(c===-1)return[str,defaultPort];const p=str.slice(c+1);if(/^\d+$/.test(p))return[str.slice(0,c),Number(p)];return[str,defaultPort] }
function extractAddress(bytes) { /* ...内容与v3.2相同... */ try{if(!bytes||bytes.length<22)throw new Error('Packet too short');const d=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),a=bytes[17],o=18+a+1,p=d.getUint16(o),t=bytes[o+2];let f=o+3,h='';switch(t){case 1:h=Array.from(bytes.slice(f,f+4)).join('.');f+=4;break;case 2:const l=bytes[f++];h=new TextDecoder().decode(bytes.slice(f,f+l));f+=l;break;case 3:case 4:const i=Array.from({length:8},(_,i)=>d.getUint16(f+i*2).toString(16));h=`[${i.join(':')}]`;f+=16;break;default:throw new Error(`Invalid address type: ${t}`)}return{host:h,port:p,payload:bytes.slice(f),sessionKey:Array.from(bytes.slice(1,17)).map(b=>b.toString(16).padStart(2,'0')).join('')}}catch(e){throw new Error(`Address parse failed: ${e.message}`)} }
async function createS5Socket(s5param, targetHost, targetPort) { /* ...S5实现与v3.2相同... */ let u=null,p=null,h=s5param;if(s5param?.includes('@')){const t=s5param.lastIndexOf('@'),e=s5param.slice(0,t);h=s5param.slice(t+1);const n=e.indexOf(':');if(n!==-1){u=e.slice(0,n);p=e.slice(n+1)}else u=e}const[a,o]=parseHostPort(h,1080),r=connect({hostname:a,port:Number(o)});await r.opened;const c=r.writable.getWriter(),s=r.readable.getReader(),l=async t=>{try{c.releaseLock()}catch{}try{s.releaseLock()}catch{}try{r?.close&&r.close()}catch{}if(t)throw t};try{await c.write(u?Uint8Array.from([5,1,2]):Uint8Array.from([5,1,0]));let t=await _readBytesFromReader(s,2,5e3);if(!t||t[1]===255)await l(new Error('S5 unsupported method'));if(t[1]===2){if(!u||!p)await l(new Error('S5 auth required'));const e=new TextEncoder().encode(u),n=new TextEncoder().encode(p),i=new Uint8Array(3+e.length+n.length);i[0]=1,i[1]=e.length,i.set(e,2),i[2+e.length]=n.length,i.set(n,3+e.length),await c.write(i);const d=await _readBytesFromReader(s,2,5e3);if(!d||d[1]!==0)await l(new Error('S5 auth failed'))}let e,n;if(/^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost))e=Uint8Array.from(targetHost.split('.').map(Number)),n=1;else if(targetHost.includes(':'))try{e=ipv6TextToBytes(targetHost),n=4}catch(t){const i=new TextEncoder().encode(targetHost);e=new Uint8Array([i.length,...i]),n=3}else{const t=new TextEncoder().encode(targetHost);e=new Uint8Array([t.length,...t]),n=3}const i=new Uint8Array(4+e.length+2),d=new DataView(i.buffer);i[0]=5,i[1]=1,i[2]=0,i[3]=n,i.set(e,4),d.setUint16(4+e.length,Number(targetPort)),await c.write(i);const g=await _readBytesFromReader(s,5,5e3);if(!g||g[1]!==0)await l(new Error(`S5 connect failed: code ${g[1]}`));return c.releaseLock(),s.releaseLock(),r}catch(t){throw await l(),t} }
async function _readBytesFromReader(reader, minBytes, timeoutMs) { /* ...内容与v3.2相同... */ const d=Date.now()+timeoutMs;let c=new Uint8Array(0);for(;Date.now()<d;){const{value:t,done:e}=await reader.read();if(e)break;if(t?.length){const n=new Uint8Array(c.length+t.length);n.set(c,0),n.set(t,c.length),c=n;if(c.length>=minBytes)return c}}return c.length>=minBytes?c:null }
function ipv6TextToBytes(addrText) { /* ...内容与v3.2相同... */ let t=addrText.startsWith('[')&&addrText.endsWith(']')?addrText.slice(1,-1):addrText;const e=t.split('::');let n=e[0]?e[0].split(':').filter(Boolean):[],s=e[1]?e[1].split(':').filter(Boolean):[],i=8-(n.length+s.length);if(i<0)throw new Error('invalid ipv6');const r=[...n,...Array(i).fill('0'),...s],o=new Uint8Array(16);for(let t=0;t<8;t++){const e=parseInt(r[t]||'0',16)||0;o[2*t]=(e>>8)&255,o[2*t+1]=255&e}return o }
function isHostInForcedS5List(h) { /* ...内容与v3.2相同... */ if(!h)return!1;h=h.toLowerCase();return CONFIG.强制S5名单.some(t=>{t=t.toLowerCase();if(t.startsWith('*.')){const e=t.slice(2);return h===e||h.endsWith('.'+e)}return h===t})}


// ==================== 4. 顶层会话处理器 (ReactionMax 核心) ====================
async function handleWebSocketSession(server, request) {
    const controller = new AbortController();
    const clientInfo = { ip: request.headers.get('CF-Connecting-IP'), colo: request.cf?.colo || 'N/A', asn: request.cf?.asn || 'N/A' };
    const closeSession = (reason) => { if (!controller.signal.aborted) { controller.abort(); telemetry.push('session_close', { client: clientInfo, reason }); }};
    server.addEventListener('close', () => closeSession('client_closed'));
    server.addEventListener('error', (err) => closeSession(`client_error: ${err.message}`));

    let reconnectCount = 0;
    let networkScore = 1.0; 
    
    try {
        telemetry.push('session_start', { client: clientInfo });
        const firstPacket = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('First packet timeout')), CONFIG.首次数据包超时);
            server.addEventListener('message', e => { clearTimeout(timer); if (e.data instanceof ArrayBuffer) resolve(new Uint8Array(e.data)); }, { once: true });
        });

        const { host: targetHost, port: targetPort, payload: initialData, sessionKey } = extractAddress(firstPacket);
        if (sessionCache.has(sessionKey)) telemetry.push('session_resume', { client: clientInfo, target: `${targetHost}:${targetPort}` });
        sessionCache.set(sessionKey);
        
        const params = parsePathParams(new URL(request.url).pathname);
        let initialConnection = true;

        while (reconnectCount < CONFIG.最大重连次数 && !controller.signal.aborted) {
            let tcpSocket = null;
            let connectionAttemptFailed = false;

            try {
                // --- 动态连接策略链 (与 v3.2 相同) ---
                const connectionFactories = []; /* ...内容与v3.2相同... */ const pyip = params['pyip']; const s5param = params['s5']; const addFactory = (name, func) => connectionFactories.push({ name, func }); const directFactory = () => connect({ hostname: targetHost, port: Number(targetPort), tls: { servername: targetHost } }); const fallbackFactory = () => { const [h, p] = parseHostPort(CONFIG.默认兜底反代, targetPort); return connect({ hostname: h, port: Number(p), tls: { servername: targetHost } }); }; const pyipFactory = () => { const [h, p] = parseHostPort(pyip, targetPort); return connect({ hostname: h, port: Number(p), tls: { servername: targetHost } }); }; const s5Factory = () => createS5Socket(s5param || CONFIG.S5账号列表[0], targetHost, targetPort); if (CONFIG.启用S5 && (isHostInForcedS5List(targetHost) || CONFIG.启用全局S5 || s5param)) { addFactory('S5', s5Factory); addFactory('Fallback', fallbackFactory); } else if (pyip && CONFIG.启用普通反代) { addFactory('Direct', directFactory); addFactory('PYIP', pyipFactory); addFactory('Fallback', fallbackFactory); } else { addFactory('Direct', directFactory); addFactory('Fallback', fallbackFactory); }
                let finalStrategy = 'Unknown';
                for (const factory of connectionFactories) {
                    try {
                        telemetry.push('connection_attempt', { target: `${targetHost}:${targetPort}`, strategy: factory.name });
                        const sock = await factory.func(); await sock.opened; tcpSocket = sock; finalStrategy = factory.name;
                        telemetry.push('connection_success', { target: `${targetHost}:${targetPort}`, strategy: finalStrategy });
                        break;
                    } catch (err) { telemetry.push('connection_failed', { target: `${targetHost}:${targetPort}`, strategy: factory.name, error: err.message }); }
                }
                if (!tcpSocket) throw new Error("All connection strategies failed.");
                
                reconnectCount = 0;
                networkScore = Math.min(1.0, networkScore + 0.15);

                if (initialConnection) {
                    if (server.readyState === WebSocket.OPEN) server.send(new Uint8Array([firstPacket[0] || 0, 0]));
                    initialConnection = false;
                }

                // --- [核心变更] Fastpath + 并行控制循环 ---
                const { readable: wsReadable, writable: wsWritable } = websocketToStreams(server);
                const wsReader = wsReadable.getReader();
                const tcpWriter = tcpSocket.writable.getWriter();
                const tcpReader = tcpSocket.readable.getReader();

                // 共享状态变量
                let state = {
                    lastActivity: Date.now(),
                    stallCount: 0,
                    bytesSinceCheck: 0,
                    lastCheck: Date.now(),
                };
                
                // Fastpath 1: 上行循环 (WS -> TCP)
                const upstreamPromise = (async () => {
                    await tcpWriter.write(initialData); // 发送首包剩余数据
                    state.lastActivity = Date.now();
                    while (!controller.signal.aborted) {
                        const { value, done } = await wsReader.read();
                        if (done) break;
                        await tcpWriter.write(value);
                        state.lastActivity = Date.now(); // 无阻塞钩子
                    }
                })();

                // Fastpath 2: 下行循环 (TCP -> WS)
                const downstreamPromise = (async () => {
                    while (!controller.signal.aborted) {
                        const { value, done } = await tcpReader.read();
                        if (done) break;
                        if (server.readyState === WebSocket.OPEN) {
                            server.send(value);
                            // 无阻塞钩子
                            state.lastActivity = Date.now();
                            state.stallCount = 0;
                            state.bytesSinceCheck += value.byteLength;
                        }
                    }
                })();

                // Loop 3: 并行控制循环
                const controlLoopPromise = (async () => {
                    while (!controller.signal.aborted) {
                        await new Promise(res => setTimeout(res, CONFIG.控制循环轮询间隔));
                        
                        const now = Date.now();

                        // 停滞检测
                        if (now - state.lastActivity > CONFIG.连接停滞超时) {
                            state.stallCount++;
                            if (state.stallCount >= CONFIG.最大停滞次数) {
                                throw new Error('Connection stalled');
                            }
                        }

                        // 主动心跳
                        if (now - state.lastActivity > CONFIG.主动心跳间隔) {
                            telemetry.push('keepalive_fired');
                            await tcpWriter.write(new Uint8Array(0));
                            state.lastActivity = now;
                        }

                        // 吞吐量监测
                        if (now - state.lastCheck > CONFIG.吞吐量监测间隔) {
                            const elapsed = (now - state.lastCheck) / 1000;
                            const throughput = state.bytesSinceCheck / 1024 / elapsed;
                            if (throughput > CONFIG.吞吐量阈值_好) networkScore = Math.min(1.0, networkScore + 0.05);
                            else if (throughput < CONFIG.吞吐量阈值_差) networkScore = Math.max(0.1, networkScore - 0.05);
                            state.lastCheck = now;
                            state.bytesSinceCheck = 0;
                        }
                    }
                })();

                await Promise.race([upstreamPromise, downstreamPromise, controlLoopPromise]);
                break;

            } catch (err) {
                telemetry.push('session_interrupted', { reason: err.message });
                connectionAttemptFailed = true;
            } finally {
                if (tcpSocket) try { tcpSocket.close(); } catch {}
            }

            if (connectionAttemptFailed) {
                reconnectCount++;
                networkScore = Math.max(0.1, networkScore - 0.2);
                let delay = Math.min(50 * Math.pow(1.5, reconnectCount), 3000) * (1.5 - networkScore * 0.5);
                await new Promise(res => setTimeout(res, Math.floor(delay)));
            }
        }
    } catch (e) {
        telemetry.push('session_crashed', { error: e.stack || e.message });
    } finally {
        closeSession('finalizer_reached');
    }
}


// ==================== 5. Worker 入口 ====================
export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const params = parsePathParams(url.pathname);
            if (params['my-key'] !== CONFIG.密钥) return new Response('Unauthorized', { status: 403 });
            
            if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
                const { 0: client, 1: server } = new WebSocketPair();
                server.accept();
                ctx.waitUntil(handleWebSocketSession(server, request));
                return new Response(null, { status: 101, webSocket: client });
            }
            
            return new Response('TitanStallion Core v3.4 (ReactionMax) is running.');
        } catch (err) {
            console.error(`Fetch handler CRASHED: ${err.stack || err.message}`);
            return new Response('Internal Server Error', { status: 500 });
        }
    }
};