// deno-fmt-ignore-file
// deno-lint-ignore-file
// This code was bundled using `deno bundle` and it's not recommended to edit it manually

class BytesList {
    #len = 0;
    #chunks = [];
    constructor(){}
    size() {
        return this.#len;
    }
    add(value, start = 0, end = value.byteLength) {
        if (value.byteLength === 0 || end - start === 0) {
            return;
        }
        checkRange(start, end, value.byteLength);
        this.#chunks.push({
            value,
            end,
            start,
            offset: this.#len
        });
        this.#len += end - start;
    }
    shift(n) {
        if (n === 0) {
            return;
        }
        if (this.#len <= n) {
            this.#chunks = [];
            this.#len = 0;
            return;
        }
        const idx = this.getChunkIndex(n);
        this.#chunks.splice(0, idx);
        const [chunk] = this.#chunks;
        if (chunk) {
            const diff = n - chunk.offset;
            chunk.start += diff;
        }
        let offset = 0;
        for (const chunk of this.#chunks){
            chunk.offset = offset;
            offset += chunk.end - chunk.start;
        }
        this.#len = offset;
    }
    getChunkIndex(pos) {
        let max = this.#chunks.length;
        let min = 0;
        while(true){
            const i = min + Math.floor((max - min) / 2);
            if (i < 0 || this.#chunks.length <= i) {
                return -1;
            }
            const { offset, start, end } = this.#chunks[i];
            const len = end - start;
            if (offset <= pos && pos < offset + len) {
                return i;
            } else if (offset + len <= pos) {
                min = i + 1;
            } else {
                max = i - 1;
            }
        }
    }
    get(i) {
        if (i < 0 || this.#len <= i) {
            throw new Error("out of range");
        }
        const idx = this.getChunkIndex(i);
        const { value, offset, start } = this.#chunks[idx];
        return value[start + i - offset];
    }
    *iterator(start = 0) {
        const startIdx = this.getChunkIndex(start);
        if (startIdx < 0) return;
        const first = this.#chunks[startIdx];
        let firstOffset = start - first.offset;
        for(let i = startIdx; i < this.#chunks.length; i++){
            const chunk = this.#chunks[i];
            for(let j = chunk.start + firstOffset; j < chunk.end; j++){
                yield chunk.value[j];
            }
            firstOffset = 0;
        }
    }
    slice(start, end = this.#len) {
        if (end === start) {
            return new Uint8Array();
        }
        checkRange(start, end, this.#len);
        const result = new Uint8Array(end - start);
        const startIdx = this.getChunkIndex(start);
        const endIdx = this.getChunkIndex(end - 1);
        let written = 0;
        for(let i = startIdx; i <= endIdx; i++){
            const { value: chunkValue, start: chunkStart, end: chunkEnd, offset: chunkOffset } = this.#chunks[i];
            const readStart = chunkStart + (i === startIdx ? start - chunkOffset : 0);
            const readEnd = i === endIdx ? end - chunkOffset + chunkStart : chunkEnd;
            const len = readEnd - readStart;
            result.set(chunkValue.subarray(readStart, readEnd), written);
            written += len;
        }
        return result;
    }
    concat() {
        const result = new Uint8Array(this.#len);
        let sum = 0;
        for (const { value, start, end } of this.#chunks){
            result.set(value.subarray(start, end), sum);
            sum += end - start;
        }
        return result;
    }
}
function checkRange(start, end, len) {
    if (start < 0 || len < start || end < 0 || len < end || end < start) {
        throw new Error("invalid range");
    }
}
function concat(...buf) {
    let length = 0;
    for (const b of buf){
        length += b.length;
    }
    const output = new Uint8Array(length);
    let index = 0;
    for (const b of buf){
        output.set(b, index);
        index += b.length;
    }
    return output;
}
function copy(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
function equalsNaive(a, b) {
    for(let i = 0; i < b.length; i++){
        if (a[i] !== b[i]) return false;
    }
    return true;
}
function equals32Bit(a, b) {
    const len = a.length;
    const compressable = Math.floor(len / 4);
    const compressedA = new Uint32Array(a.buffer, 0, compressable);
    const compressedB = new Uint32Array(b.buffer, 0, compressable);
    for(let i = compressable * 4; i < len; i++){
        if (a[i] !== b[i]) return false;
    }
    for(let i = 0; i < compressedA.length; i++){
        if (compressedA[i] !== compressedB[i]) return false;
    }
    return true;
}
function equals(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    return a.length < 1000 ? equalsNaive(a, b) : equals32Bit(a, b);
}
class DenoStdInternalError extends Error {
    constructor(message){
        super(message);
        this.name = "DenoStdInternalError";
    }
}
function assert(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError(msg);
    }
}
function timingSafeEqual(a, b) {
    if (a.byteLength !== b.byteLength) {
        return false;
    }
    if (!(a instanceof DataView)) {
        a = ArrayBuffer.isView(a) ? new DataView(a.buffer, a.byteOffset, a.byteLength) : new DataView(a);
    }
    if (!(b instanceof DataView)) {
        b = ArrayBuffer.isView(b) ? new DataView(b.buffer, b.byteOffset, b.byteLength) : new DataView(b);
    }
    assert(a instanceof DataView);
    assert(b instanceof DataView);
    const length = a.byteLength;
    let out = 0;
    let i = -1;
    while(++i < length){
        out |= a.getUint8(i) ^ b.getUint8(i);
    }
    return out === 0;
}
const base64abc = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "+",
    "/"
];
function encode(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i;
    const l = uint8.length;
    for(i = 2; i < l; i += 3){
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 0x0f) << 2 | uint8[i] >> 6];
        result += base64abc[uint8[i] & 0x3f];
    }
    if (i === l + 1) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4];
        result += "==";
    }
    if (i === l) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 0x0f) << 2];
        result += "=";
    }
    return result;
}
function convertBase64ToBase64url(b64) {
    return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function encode1(data) {
    return convertBase64ToBase64url(encode(data));
}
const encoder = new TextEncoder();
function importKey(key) {
    if (typeof key === "string") {
        key = encoder.encode(key);
    } else if (Array.isArray(key)) {
        key = new Uint8Array(key);
    }
    return crypto.subtle.importKey("raw", key, {
        name: "HMAC",
        hash: {
            name: "SHA-256"
        }
    }, true, [
        "sign",
        "verify"
    ]);
}
function sign(data, key) {
    if (typeof data === "string") {
        data = encoder.encode(data);
    } else if (Array.isArray(data)) {
        data = Uint8Array.from(data);
    }
    return crypto.subtle.sign("HMAC", key, data);
}
async function compare(a, b) {
    const key = new Uint8Array(32);
    globalThis.crypto.getRandomValues(key);
    const cryptoKey = await importKey(key);
    const ah = await sign(a, cryptoKey);
    const bh = await sign(b, cryptoKey);
    return timingSafeEqual(ah, bh);
}
class KeyStack {
    #cryptoKeys = new Map();
    #keys;
    async #toCryptoKey(key) {
        if (!this.#cryptoKeys.has(key)) {
            this.#cryptoKeys.set(key, await importKey(key));
        }
        return this.#cryptoKeys.get(key);
    }
    get length() {
        return this.#keys.length;
    }
    constructor(keys){
        const values = Array.isArray(keys) ? keys : [
            ...keys
        ];
        if (!values.length) {
            throw new TypeError("keys must contain at least one value");
        }
        this.#keys = values;
    }
    async sign(data) {
        const key = await this.#toCryptoKey(this.#keys[0]);
        return encode1(await sign(data, key));
    }
    async verify(data, digest) {
        return await this.indexOf(data, digest) > -1;
    }
    async indexOf(data, digest) {
        for(let i = 0; i < this.#keys.length; i++){
            const cryptoKey = await this.#toCryptoKey(this.#keys[i]);
            if (await compare(digest, encode1(await sign(data, cryptoKey)))) {
                return i;
            }
        }
        return -1;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { length } = this;
        return `${this.constructor.name} ${inspect({
            length
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { length } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            length
        }, newOptions)}`;
    }
}
const FIELD_CONTENT_REGEXP = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
const KEY_REGEXP = /(?:^|;) *([^=]*)=[^;]*/g;
const SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i;
const matchCache = {};
function getPattern(name) {
    if (name in matchCache) {
        return matchCache[name];
    }
    return matchCache[name] = new RegExp(`(?:^|;) *${name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}=([^;]*)`);
}
function pushCookie(values, cookie) {
    if (cookie.overwrite) {
        for(let i = values.length - 1; i >= 0; i--){
            if (values[i].indexOf(`${cookie.name}=`) === 0) {
                values.splice(i, 1);
            }
        }
    }
    values.push(cookie.toHeaderValue());
}
function validateCookieProperty(key, value) {
    if (value && !FIELD_CONTENT_REGEXP.test(value)) {
        throw new TypeError(`The "${key}" of the cookie (${value}) is invalid.`);
    }
}
class Cookie {
    domain;
    expires;
    httpOnly = true;
    maxAge;
    name;
    overwrite = false;
    path = "/";
    sameSite = false;
    secure = false;
    signed;
    value;
    constructor(name, value, attributes){
        validateCookieProperty("name", name);
        this.name = name;
        validateCookieProperty("value", value);
        this.value = value ?? "";
        Object.assign(this, attributes);
        if (!this.value) {
            this.expires = new Date(0);
            this.maxAge = undefined;
        }
        validateCookieProperty("path", this.path);
        validateCookieProperty("domain", this.domain);
        if (this.sameSite && typeof this.sameSite === "string" && !SAME_SITE_REGEXP.test(this.sameSite)) {
            throw new TypeError(`The "sameSite" of the cookie ("${this.sameSite}") is invalid.`);
        }
    }
    toHeaderValue() {
        let value = this.toString();
        if (this.maxAge) {
            this.expires = new Date(Date.now() + this.maxAge * 1000);
        }
        if (this.path) {
            value += `; path=${this.path}`;
        }
        if (this.expires) {
            value += `; expires=${this.expires.toUTCString()}`;
        }
        if (this.domain) {
            value += `; domain=${this.domain}`;
        }
        if (this.sameSite) {
            value += `; samesite=${this.sameSite === true ? "strict" : this.sameSite.toLowerCase()}`;
        }
        if (this.secure) {
            value += "; secure";
        }
        if (this.httpOnly) {
            value += "; httponly";
        }
        return value;
    }
    toString() {
        return `${this.name}=${this.value}`;
    }
}
const cookieMapHeadersInitSymbol = Symbol.for("Deno.std.cookieMap.headersInit");
const keys = Symbol("#keys");
const requestHeaders = Symbol("#requestHeaders");
const responseHeaders = Symbol("#responseHeaders");
const isSecure = Symbol("#secure");
const requestKeys = Symbol("#requestKeys");
class CookieMapBase {
    [keys];
    [requestHeaders];
    [responseHeaders];
    [isSecure];
    [requestKeys]() {
        if (this[keys]) {
            return this[keys];
        }
        const result = this[keys] = [];
        const header = this[requestHeaders].get("cookie");
        if (!header) {
            return result;
        }
        let matches;
        while(matches = KEY_REGEXP.exec(header)){
            const [, key] = matches;
            result.push(key);
        }
        return result;
    }
    constructor(request, options){
        this[requestHeaders] = "headers" in request ? request.headers : request;
        const { secure = false, response = new Headers() } = options;
        this[responseHeaders] = "headers" in response ? response.headers : response;
        this[isSecure] = secure;
    }
    [cookieMapHeadersInitSymbol]() {
        const init = [];
        for (const [key, value] of this[responseHeaders]){
            if (key === "set-cookie") {
                init.push([
                    key,
                    value
                ]);
            }
        }
        return init;
    }
    [Symbol.for("Deno.customInspect")]() {
        return `${this.constructor.name} []`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect([], newOptions)}`;
    }
}
class CookieMap extends CookieMapBase {
    get size() {
        return [
            ...this
        ].length;
    }
    constructor(request, options = {}){
        super(request, options);
    }
    clear(options = {}) {
        for (const key of this.keys()){
            this.set(key, null, options);
        }
    }
    delete(key, options = {}) {
        this.set(key, null, options);
        return true;
    }
    get(key) {
        const headerValue = this[requestHeaders].get("cookie");
        if (!headerValue) {
            return undefined;
        }
        const match = headerValue.match(getPattern(key));
        if (!match) {
            return undefined;
        }
        const [, value] = match;
        return value;
    }
    has(key) {
        const headerValue = this[requestHeaders].get("cookie");
        if (!headerValue) {
            return false;
        }
        return getPattern(key).test(headerValue);
    }
    set(key, value, options = {}) {
        const resHeaders = this[responseHeaders];
        const values = [];
        for (const [key, value] of resHeaders){
            if (key === "set-cookie") {
                values.push(value);
            }
        }
        const secure = this[isSecure];
        if (!secure && options.secure && !options.ignoreInsecure) {
            throw new TypeError("Cannot send secure cookie over unencrypted connection.");
        }
        const cookie = new Cookie(key, value, options);
        cookie.secure = options.secure ?? secure;
        pushCookie(values, cookie);
        resHeaders.delete("set-cookie");
        for (const value of values){
            resHeaders.append("set-cookie", value);
        }
        return this;
    }
    entries() {
        return this[Symbol.iterator]();
    }
    *keys() {
        for (const [key] of this){
            yield key;
        }
    }
    *values() {
        for (const [, value] of this){
            yield value;
        }
    }
    *[Symbol.iterator]() {
        const keys = this[requestKeys]();
        for (const key of keys){
            const value = this.get(key);
            if (value) {
                yield [
                    key,
                    value
                ];
            }
        }
    }
}
class SecureCookieMap extends CookieMapBase {
    #keyRing;
    get size() {
        return (async ()=>{
            let size = 0;
            for await (const _ of this){
                size++;
            }
            return size;
        })();
    }
    constructor(request, options = {}){
        super(request, options);
        const { keys } = options;
        this.#keyRing = keys;
    }
    async clear(options) {
        for await (const key of this.keys()){
            await this.set(key, null, options);
        }
    }
    async delete(key, options = {}) {
        await this.set(key, null, options);
        return true;
    }
    async get(key, options = {}) {
        const signed = options.signed ?? !!this.#keyRing;
        const nameSig = `${key}.sig`;
        const header = this[requestHeaders].get("cookie");
        if (!header) {
            return;
        }
        const match = header.match(getPattern(key));
        if (!match) {
            return;
        }
        const [, value] = match;
        if (!signed) {
            return value;
        }
        const digest = await this.get(nameSig, {
            signed: false
        });
        if (!digest) {
            return;
        }
        const data = `${key}=${value}`;
        if (!this.#keyRing) {
            throw new TypeError("key ring required for signed cookies");
        }
        const index = await this.#keyRing.indexOf(data, digest);
        if (index < 0) {
            await this.delete(nameSig, {
                path: "/",
                signed: false
            });
        } else {
            if (index) {
                await this.set(nameSig, await this.#keyRing.sign(data), {
                    signed: false
                });
            }
            return value;
        }
    }
    async has(key, options = {}) {
        const signed = options.signed ?? !!this.#keyRing;
        const nameSig = `${key}.sig`;
        const header = this[requestHeaders].get("cookie");
        if (!header) {
            return false;
        }
        const match = header.match(getPattern(key));
        if (!match) {
            return false;
        }
        if (!signed) {
            return true;
        }
        const digest = await this.get(nameSig, {
            signed: false
        });
        if (!digest) {
            return false;
        }
        const [, value] = match;
        const data = `${key}=${value}`;
        if (!this.#keyRing) {
            throw new TypeError("key ring required for signed cookies");
        }
        const index = await this.#keyRing.indexOf(data, digest);
        if (index < 0) {
            await this.delete(nameSig, {
                path: "/",
                signed: false
            });
            return false;
        } else {
            if (index) {
                await this.set(nameSig, await this.#keyRing.sign(data), {
                    signed: false
                });
            }
            return true;
        }
    }
    async set(key, value, options = {}) {
        const resHeaders = this[responseHeaders];
        const headers = [];
        for (const [key, value] of resHeaders.entries()){
            if (key === "set-cookie") {
                headers.push(value);
            }
        }
        const secure = this[isSecure];
        const signed = options.signed ?? !!this.#keyRing;
        if (!secure && options.secure && !options.ignoreInsecure) {
            throw new TypeError("Cannot send secure cookie over unencrypted connection.");
        }
        const cookie = new Cookie(key, value, options);
        cookie.secure = options.secure ?? secure;
        pushCookie(headers, cookie);
        if (signed) {
            if (!this.#keyRing) {
                throw new TypeError("keys required for signed cookies.");
            }
            cookie.value = await this.#keyRing.sign(cookie.toString());
            cookie.name += ".sig";
            pushCookie(headers, cookie);
        }
        resHeaders.delete("set-cookie");
        for (const header of headers){
            resHeaders.append("set-cookie", header);
        }
        return this;
    }
    entries() {
        return this[Symbol.asyncIterator]();
    }
    async *keys() {
        for await (const [key] of this){
            yield key;
        }
    }
    async *values() {
        for await (const [, value] of this){
            yield value;
        }
    }
    async *[Symbol.asyncIterator]() {
        const keys = this[requestKeys]();
        for (const key of keys){
            const value = await this.get(key);
            if (value) {
                yield [
                    key,
                    value
                ];
            }
        }
    }
}
var Status;
(function(Status) {
    Status[Status["Continue"] = 100] = "Continue";
    Status[Status["SwitchingProtocols"] = 101] = "SwitchingProtocols";
    Status[Status["Processing"] = 102] = "Processing";
    Status[Status["EarlyHints"] = 103] = "EarlyHints";
    Status[Status["OK"] = 200] = "OK";
    Status[Status["Created"] = 201] = "Created";
    Status[Status["Accepted"] = 202] = "Accepted";
    Status[Status["NonAuthoritativeInfo"] = 203] = "NonAuthoritativeInfo";
    Status[Status["NoContent"] = 204] = "NoContent";
    Status[Status["ResetContent"] = 205] = "ResetContent";
    Status[Status["PartialContent"] = 206] = "PartialContent";
    Status[Status["MultiStatus"] = 207] = "MultiStatus";
    Status[Status["AlreadyReported"] = 208] = "AlreadyReported";
    Status[Status["IMUsed"] = 226] = "IMUsed";
    Status[Status["MultipleChoices"] = 300] = "MultipleChoices";
    Status[Status["MovedPermanently"] = 301] = "MovedPermanently";
    Status[Status["Found"] = 302] = "Found";
    Status[Status["SeeOther"] = 303] = "SeeOther";
    Status[Status["NotModified"] = 304] = "NotModified";
    Status[Status["UseProxy"] = 305] = "UseProxy";
    Status[Status["TemporaryRedirect"] = 307] = "TemporaryRedirect";
    Status[Status["PermanentRedirect"] = 308] = "PermanentRedirect";
    Status[Status["BadRequest"] = 400] = "BadRequest";
    Status[Status["Unauthorized"] = 401] = "Unauthorized";
    Status[Status["PaymentRequired"] = 402] = "PaymentRequired";
    Status[Status["Forbidden"] = 403] = "Forbidden";
    Status[Status["NotFound"] = 404] = "NotFound";
    Status[Status["MethodNotAllowed"] = 405] = "MethodNotAllowed";
    Status[Status["NotAcceptable"] = 406] = "NotAcceptable";
    Status[Status["ProxyAuthRequired"] = 407] = "ProxyAuthRequired";
    Status[Status["RequestTimeout"] = 408] = "RequestTimeout";
    Status[Status["Conflict"] = 409] = "Conflict";
    Status[Status["Gone"] = 410] = "Gone";
    Status[Status["LengthRequired"] = 411] = "LengthRequired";
    Status[Status["PreconditionFailed"] = 412] = "PreconditionFailed";
    Status[Status["RequestEntityTooLarge"] = 413] = "RequestEntityTooLarge";
    Status[Status["RequestURITooLong"] = 414] = "RequestURITooLong";
    Status[Status["UnsupportedMediaType"] = 415] = "UnsupportedMediaType";
    Status[Status["RequestedRangeNotSatisfiable"] = 416] = "RequestedRangeNotSatisfiable";
    Status[Status["ExpectationFailed"] = 417] = "ExpectationFailed";
    Status[Status["Teapot"] = 418] = "Teapot";
    Status[Status["MisdirectedRequest"] = 421] = "MisdirectedRequest";
    Status[Status["UnprocessableEntity"] = 422] = "UnprocessableEntity";
    Status[Status["Locked"] = 423] = "Locked";
    Status[Status["FailedDependency"] = 424] = "FailedDependency";
    Status[Status["TooEarly"] = 425] = "TooEarly";
    Status[Status["UpgradeRequired"] = 426] = "UpgradeRequired";
    Status[Status["PreconditionRequired"] = 428] = "PreconditionRequired";
    Status[Status["TooManyRequests"] = 429] = "TooManyRequests";
    Status[Status["RequestHeaderFieldsTooLarge"] = 431] = "RequestHeaderFieldsTooLarge";
    Status[Status["UnavailableForLegalReasons"] = 451] = "UnavailableForLegalReasons";
    Status[Status["InternalServerError"] = 500] = "InternalServerError";
    Status[Status["NotImplemented"] = 501] = "NotImplemented";
    Status[Status["BadGateway"] = 502] = "BadGateway";
    Status[Status["ServiceUnavailable"] = 503] = "ServiceUnavailable";
    Status[Status["GatewayTimeout"] = 504] = "GatewayTimeout";
    Status[Status["HTTPVersionNotSupported"] = 505] = "HTTPVersionNotSupported";
    Status[Status["VariantAlsoNegotiates"] = 506] = "VariantAlsoNegotiates";
    Status[Status["InsufficientStorage"] = 507] = "InsufficientStorage";
    Status[Status["LoopDetected"] = 508] = "LoopDetected";
    Status[Status["NotExtended"] = 510] = "NotExtended";
    Status[Status["NetworkAuthenticationRequired"] = 511] = "NetworkAuthenticationRequired";
})(Status || (Status = {}));
const STATUS_TEXT = {
    [Status.Accepted]: "Accepted",
    [Status.AlreadyReported]: "Already Reported",
    [Status.BadGateway]: "Bad Gateway",
    [Status.BadRequest]: "Bad Request",
    [Status.Conflict]: "Conflict",
    [Status.Continue]: "Continue",
    [Status.Created]: "Created",
    [Status.EarlyHints]: "Early Hints",
    [Status.ExpectationFailed]: "Expectation Failed",
    [Status.FailedDependency]: "Failed Dependency",
    [Status.Forbidden]: "Forbidden",
    [Status.Found]: "Found",
    [Status.GatewayTimeout]: "Gateway Timeout",
    [Status.Gone]: "Gone",
    [Status.HTTPVersionNotSupported]: "HTTP Version Not Supported",
    [Status.IMUsed]: "IM Used",
    [Status.InsufficientStorage]: "Insufficient Storage",
    [Status.InternalServerError]: "Internal Server Error",
    [Status.LengthRequired]: "Length Required",
    [Status.Locked]: "Locked",
    [Status.LoopDetected]: "Loop Detected",
    [Status.MethodNotAllowed]: "Method Not Allowed",
    [Status.MisdirectedRequest]: "Misdirected Request",
    [Status.MovedPermanently]: "Moved Permanently",
    [Status.MultiStatus]: "Multi Status",
    [Status.MultipleChoices]: "Multiple Choices",
    [Status.NetworkAuthenticationRequired]: "Network Authentication Required",
    [Status.NoContent]: "No Content",
    [Status.NonAuthoritativeInfo]: "Non Authoritative Info",
    [Status.NotAcceptable]: "Not Acceptable",
    [Status.NotExtended]: "Not Extended",
    [Status.NotFound]: "Not Found",
    [Status.NotImplemented]: "Not Implemented",
    [Status.NotModified]: "Not Modified",
    [Status.OK]: "OK",
    [Status.PartialContent]: "Partial Content",
    [Status.PaymentRequired]: "Payment Required",
    [Status.PermanentRedirect]: "Permanent Redirect",
    [Status.PreconditionFailed]: "Precondition Failed",
    [Status.PreconditionRequired]: "Precondition Required",
    [Status.Processing]: "Processing",
    [Status.ProxyAuthRequired]: "Proxy Auth Required",
    [Status.RequestEntityTooLarge]: "Request Entity Too Large",
    [Status.RequestHeaderFieldsTooLarge]: "Request Header Fields Too Large",
    [Status.RequestTimeout]: "Request Timeout",
    [Status.RequestURITooLong]: "Request URI Too Long",
    [Status.RequestedRangeNotSatisfiable]: "Requested Range Not Satisfiable",
    [Status.ResetContent]: "Reset Content",
    [Status.SeeOther]: "See Other",
    [Status.ServiceUnavailable]: "Service Unavailable",
    [Status.SwitchingProtocols]: "Switching Protocols",
    [Status.Teapot]: "I'm a teapot",
    [Status.TemporaryRedirect]: "Temporary Redirect",
    [Status.TooEarly]: "Too Early",
    [Status.TooManyRequests]: "Too Many Requests",
    [Status.Unauthorized]: "Unauthorized",
    [Status.UnavailableForLegalReasons]: "Unavailable For Legal Reasons",
    [Status.UnprocessableEntity]: "Unprocessable Entity",
    [Status.UnsupportedMediaType]: "Unsupported Media Type",
    [Status.UpgradeRequired]: "Upgrade Required",
    [Status.UseProxy]: "Use Proxy",
    [Status.VariantAlsoNegotiates]: "Variant Also Negotiates"
};
function isClientErrorStatus(status) {
    return status >= 400 && status < 500;
}
const ERROR_STATUS_MAP = {
    "BadRequest": 400,
    "Unauthorized": 401,
    "PaymentRequired": 402,
    "Forbidden": 403,
    "NotFound": 404,
    "MethodNotAllowed": 405,
    "NotAcceptable": 406,
    "ProxyAuthRequired": 407,
    "RequestTimeout": 408,
    "Conflict": 409,
    "Gone": 410,
    "LengthRequired": 411,
    "PreconditionFailed": 412,
    "RequestEntityTooLarge": 413,
    "RequestURITooLong": 414,
    "UnsupportedMediaType": 415,
    "RequestedRangeNotSatisfiable": 416,
    "ExpectationFailed": 417,
    "Teapot": 418,
    "MisdirectedRequest": 421,
    "UnprocessableEntity": 422,
    "Locked": 423,
    "FailedDependency": 424,
    "UpgradeRequired": 426,
    "PreconditionRequired": 428,
    "TooManyRequests": 429,
    "RequestHeaderFieldsTooLarge": 431,
    "UnavailableForLegalReasons": 451,
    "InternalServerError": 500,
    "NotImplemented": 501,
    "BadGateway": 502,
    "ServiceUnavailable": 503,
    "GatewayTimeout": 504,
    "HTTPVersionNotSupported": 505,
    "VariantAlsoNegotiates": 506,
    "InsufficientStorage": 507,
    "LoopDetected": 508,
    "NotExtended": 510,
    "NetworkAuthenticationRequired": 511
};
class HttpError extends Error {
    #status = Status.InternalServerError;
    #expose;
    #headers;
    constructor(message = "Http Error", options){
        super(message, options);
        this.#expose = options?.expose === undefined ? isClientErrorStatus(this.status) : options.expose;
        if (options?.headers) {
            this.#headers = new Headers(options.headers);
        }
    }
    get expose() {
        return this.#expose;
    }
    get headers() {
        return this.#headers;
    }
    get status() {
        return this.#status;
    }
}
function createHttpErrorConstructor(status) {
    const name = `${Status[status]}Error`;
    const ErrorCtor = class extends HttpError {
        constructor(message = STATUS_TEXT[status], options){
            super(message, options);
            Object.defineProperty(this, "name", {
                configurable: true,
                enumerable: false,
                value: name,
                writable: true
            });
        }
        get status() {
            return status;
        }
    };
    return ErrorCtor;
}
const errors = {};
for (const [key, value] of Object.entries(ERROR_STATUS_MAP)){
    errors[key] = createHttpErrorConstructor(value);
}
function createHttpError(status = Status.InternalServerError, message, options) {
    return new errors[Status[status]](message, options);
}
const encoder1 = new TextEncoder();
const DEFAULT_ALGORITHM = "SHA-256";
function isFileInfo(value) {
    return Boolean(value && typeof value === "object" && "mtime" in value && "size" in value);
}
async function calcEntity(entity, { algorithm = DEFAULT_ALGORITHM }) {
    if (entity.length === 0) {
        return `0-47DEQpj8HBSa+/TImW+5JCeuQeR`;
    }
    if (typeof entity === "string") {
        entity = encoder1.encode(entity);
    }
    const hash = encode(await crypto.subtle.digest(algorithm, entity)).substring(0, 27);
    return `${entity.length.toString(16)}-${hash}`;
}
async function calcFileInfo(fileInfo, { algorithm = DEFAULT_ALGORITHM }) {
    if (fileInfo.mtime) {
        const hash = encode(await crypto.subtle.digest(algorithm, encoder1.encode(fileInfo.mtime.toJSON()))).substring(0, 27);
        return `${fileInfo.size.toString(16)}-${hash}`;
    }
}
async function calculate(entity, options = {}) {
    const weak = options.weak ?? isFileInfo(entity);
    const tag = await (isFileInfo(entity) ? calcFileInfo(entity, options) : calcEntity(entity, options));
    return tag ? weak ? `W/"${tag}"` : `"${tag}"` : undefined;
}
function ifNoneMatch(value, etag) {
    if (!value || !etag) {
        return true;
    }
    if (value.trim() === "*") {
        return false;
    }
    etag = etag.startsWith("W/") ? etag.slice(2) : etag;
    const tags = value.split(/\s*,\s*/).map((tag)=>tag.startsWith("W/") ? tag.slice(2) : tag);
    return !tags.includes(etag);
}
function compareSpecs(a, b) {
    return b.q - a.q || (b.s ?? 0) - (a.s ?? 0) || (a.o ?? 0) - (b.o ?? 0) || a.i - b.i || 0;
}
function isQuality(spec) {
    return spec.q > 0;
}
const simpleEncodingRegExp = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
function parseEncoding(str, i) {
    const match = simpleEncodingRegExp.exec(str);
    if (!match) {
        return undefined;
    }
    const encoding = match[1];
    let q = 1;
    if (match[2]) {
        const params = match[2].split(";");
        for (const param of params){
            const p = param.trim().split("=");
            if (p[0] === "q") {
                q = parseFloat(p[1]);
                break;
            }
        }
    }
    return {
        encoding,
        q,
        i
    };
}
function specify(encoding, spec, i = -1) {
    if (!spec.encoding) {
        return;
    }
    let s = 0;
    if (spec.encoding.toLocaleLowerCase() === encoding.toLocaleLowerCase()) {
        s = 1;
    } else if (spec.encoding !== "*") {
        return;
    }
    return {
        i,
        o: spec.i,
        q: spec.q,
        s
    };
}
function parseAcceptEncoding(accept) {
    const accepts = accept.split(",");
    const parsedAccepts = [];
    let hasIdentity = false;
    let minQuality = 1;
    for(let i = 0; i < accepts.length; i++){
        const encoding = parseEncoding(accepts[i].trim(), i);
        if (encoding) {
            parsedAccepts.push(encoding);
            hasIdentity = hasIdentity || !!specify("identity", encoding);
            minQuality = Math.min(minQuality, encoding.q || 1);
        }
    }
    if (!hasIdentity) {
        parsedAccepts.push({
            encoding: "identity",
            q: minQuality,
            i: accepts.length - 1
        });
    }
    return parsedAccepts;
}
function getEncodingPriority(encoding, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: 0
    };
    for (const s of accepted){
        const spec = specify(encoding, s, index);
        if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredEncodings(accept, provided) {
    const accepts = parseAcceptEncoding(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.encoding);
    }
    const priorities = provided.map((type, index)=>getEncodingPriority(type, accepts, index));
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]);
}
const SIMPLE_LANGUAGE_REGEXP = /^\s*([^\s\-;]+)(?:-([^\s;]+))?\s*(?:;(.*))?$/;
function parseLanguage(str, i) {
    const match = SIMPLE_LANGUAGE_REGEXP.exec(str);
    if (!match) {
        return undefined;
    }
    const [, prefix, suffix] = match;
    const full = suffix ? `${prefix}-${suffix}` : prefix;
    let q = 1;
    if (match[3]) {
        const params = match[3].split(";");
        for (const param of params){
            const [key, value] = param.trim().split("=");
            if (key === "q") {
                q = parseFloat(value);
                break;
            }
        }
    }
    return {
        prefix,
        suffix,
        full,
        q,
        i
    };
}
function parseAcceptLanguage(accept) {
    const accepts = accept.split(",");
    const result = [];
    for(let i = 0; i < accepts.length; i++){
        const language = parseLanguage(accepts[i].trim(), i);
        if (language) {
            result.push(language);
        }
    }
    return result;
}
function specify1(language, spec, i) {
    const p = parseLanguage(language, i);
    if (!p) {
        return undefined;
    }
    let s = 0;
    if (spec.full.toLowerCase() === p.full.toLowerCase()) {
        s |= 4;
    } else if (spec.prefix.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 2;
    } else if (spec.full.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 1;
    } else if (spec.full !== "*") {
        return;
    }
    return {
        i,
        o: spec.i,
        q: spec.q,
        s
    };
}
function getLanguagePriority(language, accepted, index) {
    let priority = {
        i: -1,
        o: -1,
        q: 0,
        s: 0
    };
    for (const accepts of accepted){
        const spec = specify1(language, accepts, index);
        if (spec && ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q || (priority.o ?? 0) - (spec.o ?? 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredLanguages(accept = "*", provided) {
    const accepts = parseAcceptLanguage(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.full);
    }
    const priorities = provided.map((type, index)=>getLanguagePriority(type, accepts, index));
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]);
}
const simpleMediaTypeRegExp = /^\s*([^\s\/;]+)\/([^;\s]+)\s*(?:;(.*))?$/;
function quoteCount(str) {
    let count = 0;
    let index = 0;
    while((index = str.indexOf(`"`, index)) !== -1){
        count++;
        index++;
    }
    return count;
}
function splitMediaTypes(accept) {
    const accepts = accept.split(",");
    let j = 0;
    for(let i = 1; i < accepts.length; i++){
        if (quoteCount(accepts[j]) % 2 === 0) {
            accepts[++j] = accepts[i];
        } else {
            accepts[j] += `,${accepts[i]}`;
        }
    }
    accepts.length = j + 1;
    return accepts;
}
function splitParameters(str) {
    const parameters = str.split(";");
    let j = 0;
    for(let i = 1; i < parameters.length; i++){
        if (quoteCount(parameters[j]) % 2 === 0) {
            parameters[++j] = parameters[i];
        } else {
            parameters[j] += `;${parameters[i]}`;
        }
    }
    parameters.length = j + 1;
    return parameters.map((p)=>p.trim());
}
function splitKeyValuePair(str) {
    const [key, value] = str.split("=");
    return [
        key.toLowerCase(),
        value
    ];
}
function parseMediaType(str, i) {
    const match = simpleMediaTypeRegExp.exec(str);
    if (!match) {
        return;
    }
    const params = Object.create(null);
    let q = 1;
    const [, type, subtype, parameters] = match;
    if (parameters) {
        const kvps = splitParameters(parameters).map(splitKeyValuePair);
        for (const [key, val] of kvps){
            const value = val && val[0] === `"` && val[val.length - 1] === `"` ? val.slice(1, val.length - 1) : val;
            if (key === "q" && value) {
                q = parseFloat(value);
                break;
            }
            params[key] = value;
        }
    }
    return {
        type,
        subtype,
        params,
        q,
        i
    };
}
function parseAccept(accept) {
    const accepts = splitMediaTypes(accept);
    const mediaTypes = [];
    for(let i = 0; i < accepts.length; i++){
        const mediaType = parseMediaType(accepts[i].trim(), i);
        if (mediaType) {
            mediaTypes.push(mediaType);
        }
    }
    return mediaTypes;
}
function getFullType(spec) {
    return `${spec.type}/${spec.subtype}`;
}
function specify2(type, spec, index) {
    const p = parseMediaType(type, index);
    if (!p) {
        return;
    }
    let s = 0;
    if (spec.type.toLowerCase() === p.type.toLowerCase()) {
        s |= 4;
    } else if (spec.type !== "*") {
        return;
    }
    if (spec.subtype.toLowerCase() === p.subtype.toLowerCase()) {
        s |= 2;
    } else if (spec.subtype !== "*") {
        return;
    }
    const keys = Object.keys(spec.params);
    if (keys.length) {
        if (keys.every((key)=>(spec.params[key] || "").toLowerCase() === (p.params[key] || "").toLowerCase())) {
            s |= 1;
        } else {
            return;
        }
    }
    return {
        i: index,
        o: spec.o,
        q: spec.q,
        s
    };
}
function getMediaTypePriority(type, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: index
    };
    for (const accepts of accepted){
        const spec = specify2(type, accepts, index);
        if (spec && ((priority.s || 0) - (spec.s || 0) || (priority.q || 0) - (spec.q || 0) || (priority.o || 0) - (spec.o || 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredMediaTypes(accept, provided) {
    const accepts = parseAccept(accept === undefined ? "*/*" : accept || "");
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map(getFullType);
    }
    const priorities = provided.map((type, index)=>{
        return getMediaTypePriority(type, accepts, index);
    });
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]);
}
function accepts(request, ...types) {
    const accept = request.headers.get("accept");
    return types.length ? accept ? preferredMediaTypes(accept, types)[0] : types[0] : accept ? preferredMediaTypes(accept) : [
        "*/*"
    ];
}
function acceptsEncodings(request, ...encodings) {
    const acceptEncoding = request.headers.get("accept-encoding");
    return encodings.length ? acceptEncoding ? preferredEncodings(acceptEncoding, encodings)[0] : encodings[0] : acceptEncoding ? preferredEncodings(acceptEncoding) : [
        "*"
    ];
}
function acceptsLanguages(request, ...langs) {
    const acceptLanguage = request.headers.get("accept-language");
    return langs.length ? acceptLanguage ? preferredLanguages(acceptLanguage, langs)[0] : langs[0] : acceptLanguage ? preferredLanguages(acceptLanguage) : [
        "*"
    ];
}
const encoder2 = new TextEncoder();
class CloseEvent extends Event {
    constructor(eventInit){
        super("close", eventInit);
    }
}
class ServerSentEvent extends Event {
    #data;
    #id;
    #type;
    constructor(type, eventInit = {}){
        super(type, eventInit);
        const { data, replacer, space } = eventInit;
        this.#type = type;
        try {
            this.#data = typeof data === "string" ? data : JSON.stringify(data, replacer, space);
        } catch (e) {
            assert(e instanceof Error);
            throw new TypeError(`data could not be coerced into a serialized string.\n  ${e.message}`);
        }
        const { id } = eventInit;
        this.#id = id;
    }
    get data() {
        return this.#data;
    }
    get id() {
        return this.#id;
    }
    toString() {
        const data = `data: ${this.#data.split("\n").join("\ndata: ")}\n`;
        return `${this.#type === "__message" ? "" : `event: ${this.#type}\n`}${this.#id ? `id: ${String(this.#id)}\n` : ""}${data}\n`;
    }
}
const RESPONSE_HEADERS = [
    [
        "Connection",
        "Keep-Alive"
    ],
    [
        "Content-Type",
        "text/event-stream"
    ],
    [
        "Cache-Control",
        "no-cache"
    ],
    [
        "Keep-Alive",
        `timeout=${Number.MAX_SAFE_INTEGER}`
    ]
];
class ServerSentEventStreamTarget extends EventTarget {
    #bodyInit;
    #closed = false;
    #controller;
    #keepAliveId;
    #error(error) {
        this.dispatchEvent(new CloseEvent({
            cancelable: false
        }));
        const errorEvent = new ErrorEvent("error", {
            error
        });
        this.dispatchEvent(errorEvent);
    }
    #push(payload) {
        if (!this.#controller) {
            this.#error(new Error("The controller has not been set."));
            return;
        }
        if (this.#closed) {
            return;
        }
        this.#controller.enqueue(encoder2.encode(payload));
    }
    get closed() {
        return this.#closed;
    }
    constructor({ keepAlive = false } = {}){
        super();
        this.#bodyInit = new ReadableStream({
            start: (controller)=>{
                this.#controller = controller;
            },
            cancel: (error)=>{
                if (error instanceof Error && error.message.includes("connection closed")) {
                    this.close();
                } else {
                    this.#error(error);
                }
            }
        });
        this.addEventListener("close", ()=>{
            this.#closed = true;
            if (this.#keepAliveId != null) {
                clearInterval(this.#keepAliveId);
                this.#keepAliveId = undefined;
            }
            if (this.#controller) {
                try {
                    this.#controller.close();
                } catch  {}
            }
        });
        if (keepAlive) {
            const interval = typeof keepAlive === "number" ? keepAlive : 30_000;
            this.#keepAliveId = setInterval(()=>{
                this.dispatchComment("keep-alive comment");
            }, interval);
        }
    }
    asResponse(responseInit) {
        return new Response(...this.asResponseInit(responseInit));
    }
    asResponseInit(responseInit = {}) {
        responseInit.headers = new Headers(responseInit.headers);
        for (const [key, value] of RESPONSE_HEADERS){
            responseInit.headers.set(key, value);
        }
        return [
            this.#bodyInit,
            responseInit
        ];
    }
    close() {
        this.dispatchEvent(new CloseEvent({
            cancelable: false
        }));
        return Promise.resolve();
    }
    dispatchComment(comment) {
        this.#push(`: ${comment.split("\n").join("\n: ")}\n\n`);
        return true;
    }
    dispatchMessage(data) {
        const event = new ServerSentEvent("__message", {
            data
        });
        return this.dispatchEvent(event);
    }
    dispatchEvent(event) {
        const dispatched = super.dispatchEvent(event);
        if (dispatched && event instanceof ServerSentEvent) {
            this.#push(String(event));
        }
        return dispatched;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            "#bodyInit": this.#bodyInit,
            "#closed": this.#closed
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            "#bodyInit": this.#bodyInit,
            "#closed": this.#closed
        }, newOptions)}`;
    }
}
const MIN_READ = 32 * 1024;
const MAX_SIZE = 2 ** 32 - 2;
class Buffer {
    #buf;
    #off = 0;
    constructor(ab){
        this.#buf = ab === undefined ? new Uint8Array(0) : new Uint8Array(ab);
    }
    bytes(options = {
        copy: true
    }) {
        if (options.copy === false) return this.#buf.subarray(this.#off);
        return this.#buf.slice(this.#off);
    }
    empty() {
        return this.#buf.byteLength <= this.#off;
    }
    get length() {
        return this.#buf.byteLength - this.#off;
    }
    get capacity() {
        return this.#buf.buffer.byteLength;
    }
    truncate(n) {
        if (n === 0) {
            this.reset();
            return;
        }
        if (n < 0 || n > this.length) {
            throw Error("bytes.Buffer: truncation out of range");
        }
        this.#reslice(this.#off + n);
    }
    reset() {
        this.#reslice(0);
        this.#off = 0;
    }
    #tryGrowByReslice(n) {
        const l = this.#buf.byteLength;
        if (n <= this.capacity - l) {
            this.#reslice(l + n);
            return l;
        }
        return -1;
    }
    #reslice(len) {
        assert(len <= this.#buf.buffer.byteLength);
        this.#buf = new Uint8Array(this.#buf.buffer, 0, len);
    }
    readSync(p) {
        if (this.empty()) {
            this.reset();
            if (p.byteLength === 0) {
                return 0;
            }
            return null;
        }
        const nread = copy(this.#buf.subarray(this.#off), p);
        this.#off += nread;
        return nread;
    }
    read(p) {
        const rr = this.readSync(p);
        return Promise.resolve(rr);
    }
    writeSync(p) {
        const m = this.#grow(p.byteLength);
        return copy(p, this.#buf, m);
    }
    write(p) {
        const n = this.writeSync(p);
        return Promise.resolve(n);
    }
    #grow(n) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n <= Math.floor(c / 2) - m) {
            copy(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n > MAX_SIZE) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE));
            copy(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n, MAX_SIZE));
        return m;
    }
    grow(n) {
        if (n < 0) {
            throw Error("Buffer.grow: negative count");
        }
        const m = this.#grow(n);
        this.#reslice(m);
    }
    async readFrom(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = await r.read(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
    readFromSync(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = r.readSync(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
}
class LimitedReader {
    reader;
    limit;
    constructor(reader, limit){
        this.reader = reader;
        this.limit = limit;
    }
    async read(p) {
        if (this.limit <= 0) {
            return null;
        }
        if (p.length > this.limit) {
            p = p.subarray(0, this.limit);
        }
        const n = await this.reader.read(p);
        if (n == null) {
            return null;
        }
        this.limit -= n;
        return n;
    }
}
BigInt(Number.MAX_SAFE_INTEGER);
new TextDecoder();
const extensions = new Map();
function consumeToken(v) {
    const notPos = indexOf(v, isNotTokenChar);
    if (notPos == -1) {
        return [
            v,
            ""
        ];
    }
    if (notPos == 0) {
        return [
            "",
            v
        ];
    }
    return [
        v.slice(0, notPos),
        v.slice(notPos)
    ];
}
function consumeValue(v) {
    if (!v) {
        return [
            "",
            v
        ];
    }
    if (v[0] !== `"`) {
        return consumeToken(v);
    }
    let value = "";
    for(let i = 1; i < v.length; i++){
        const r = v[i];
        if (r === `"`) {
            return [
                value,
                v.slice(i + 1)
            ];
        }
        if (r === "\\" && i + 1 < v.length && isTSpecial(v[i + 1])) {
            value += v[i + 1];
            i++;
            continue;
        }
        if (r === "\r" || r === "\n") {
            return [
                "",
                v
            ];
        }
        value += v[i];
    }
    return [
        "",
        v
    ];
}
function consumeMediaParam(v) {
    let rest = v.trimStart();
    if (!rest.startsWith(";")) {
        return [
            "",
            "",
            v
        ];
    }
    rest = rest.slice(1);
    rest = rest.trimStart();
    let param;
    [param, rest] = consumeToken(rest);
    param = param.toLowerCase();
    if (!param) {
        return [
            "",
            "",
            v
        ];
    }
    rest = rest.slice(1);
    rest = rest.trimStart();
    const [value, rest2] = consumeValue(rest);
    if (value == "" && rest2 === rest) {
        return [
            "",
            "",
            v
        ];
    }
    rest = rest2;
    return [
        param,
        value,
        rest
    ];
}
function decode2331Encoding(v) {
    const sv = v.split(`'`, 3);
    if (sv.length !== 3) {
        return undefined;
    }
    const charset = sv[0].toLowerCase();
    if (!charset) {
        return undefined;
    }
    if (charset != "us-ascii" && charset != "utf-8") {
        return undefined;
    }
    const encv = decodeURI(sv[2]);
    if (!encv) {
        return undefined;
    }
    return encv;
}
function indexOf(s, fn) {
    let i = -1;
    for (const v of s){
        i++;
        if (fn(v)) {
            return i;
        }
    }
    return -1;
}
function isIterator(obj) {
    if (obj == null) {
        return false;
    }
    return typeof obj[Symbol.iterator] === "function";
}
function isToken(s) {
    if (!s) {
        return false;
    }
    return indexOf(s, isNotTokenChar) < 0;
}
function isNotTokenChar(r) {
    return !isTokenChar(r);
}
function isTokenChar(r) {
    const code = r.charCodeAt(0);
    return code > 0x20 && code < 0x7f && !isTSpecial(r);
}
function isTSpecial(r) {
    return `()<>@,;:\\"/[]?=`.includes(r[0]);
}
const CHAR_CODE_SPACE = " ".charCodeAt(0);
const CHAR_CODE_TILDE = "~".charCodeAt(0);
function needsEncoding(s) {
    for (const b of s){
        const charCode = b.charCodeAt(0);
        if ((charCode < CHAR_CODE_SPACE || charCode > CHAR_CODE_TILDE) && b !== "\t") {
            return true;
        }
    }
    return false;
}
function parseMediaType1(v) {
    const [base] = v.split(";");
    const mediaType = base.toLowerCase().trim();
    const params = {};
    const continuation = new Map();
    v = v.slice(base.length);
    while(v.length){
        v = v.trimStart();
        if (v.length === 0) {
            break;
        }
        const [key, value, rest] = consumeMediaParam(v);
        if (!key) {
            if (rest.trim() === ";") {
                break;
            }
            throw new TypeError("Invalid media parameter.");
        }
        let pmap = params;
        const [baseName, rest2] = key.split("*");
        if (baseName && rest2 != null) {
            if (!continuation.has(baseName)) {
                continuation.set(baseName, {});
            }
            pmap = continuation.get(baseName);
        }
        if (key in pmap) {
            throw new TypeError("Duplicate key parsed.");
        }
        pmap[key] = value;
        v = rest;
    }
    let str = "";
    for (const [key, pieceMap] of continuation){
        const singlePartKey = `${key}*`;
        const v = pieceMap[singlePartKey];
        if (v) {
            const decv = decode2331Encoding(v);
            if (decv) {
                params[key] = decv;
            }
            continue;
        }
        str = "";
        let valid = false;
        for(let n = 0;; n++){
            const simplePart = `${key}*${n}`;
            let v = pieceMap[simplePart];
            if (v) {
                valid = true;
                str += v;
                continue;
            }
            const encodedPart = `${simplePart}*`;
            v = pieceMap[encodedPart];
            if (!v) {
                break;
            }
            valid = true;
            if (n === 0) {
                const decv = decode2331Encoding(v);
                if (decv) {
                    str += decv;
                }
            } else {
                const decv = decodeURI(v);
                str += decv;
            }
        }
        if (valid) {
            params[key] = str;
        }
    }
    return Object.keys(params).length ? [
        mediaType,
        params
    ] : [
        mediaType,
        undefined
    ];
}
const __default = {
    "application/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "application/3gpdash-qoe-report+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/3gpp-ims+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/3gpphal+json": {
        "source": "iana",
        "compressible": true
    },
    "application/3gpphalforms+json": {
        "source": "iana",
        "compressible": true
    },
    "application/a2l": {
        "source": "iana"
    },
    "application/ace+cbor": {
        "source": "iana"
    },
    "application/activemessage": {
        "source": "iana"
    },
    "application/activity+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-costmap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-costmapfilter+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-directory+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointcost+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointcostparams+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointprop+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointpropparams+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-error+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-networkmap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-networkmapfilter+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-updatestreamcontrol+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-updatestreamparams+json": {
        "source": "iana",
        "compressible": true
    },
    "application/aml": {
        "source": "iana"
    },
    "application/andrew-inset": {
        "source": "iana",
        "extensions": [
            "ez"
        ]
    },
    "application/applefile": {
        "source": "iana"
    },
    "application/applixware": {
        "source": "apache",
        "extensions": [
            "aw"
        ]
    },
    "application/at+jwt": {
        "source": "iana"
    },
    "application/atf": {
        "source": "iana"
    },
    "application/atfx": {
        "source": "iana"
    },
    "application/atom+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atom"
        ]
    },
    "application/atomcat+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atomcat"
        ]
    },
    "application/atomdeleted+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atomdeleted"
        ]
    },
    "application/atomicmail": {
        "source": "iana"
    },
    "application/atomsvc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atomsvc"
        ]
    },
    "application/atsc-dwd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dwd"
        ]
    },
    "application/atsc-dynamic-event-message": {
        "source": "iana"
    },
    "application/atsc-held+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "held"
        ]
    },
    "application/atsc-rdt+json": {
        "source": "iana",
        "compressible": true
    },
    "application/atsc-rsat+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rsat"
        ]
    },
    "application/atxml": {
        "source": "iana"
    },
    "application/auth-policy+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/bacnet-xdd+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/batch-smtp": {
        "source": "iana"
    },
    "application/bdoc": {
        "compressible": false,
        "extensions": [
            "bdoc"
        ]
    },
    "application/beep+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/calendar+json": {
        "source": "iana",
        "compressible": true
    },
    "application/calendar+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xcs"
        ]
    },
    "application/call-completion": {
        "source": "iana"
    },
    "application/cals-1840": {
        "source": "iana"
    },
    "application/captive+json": {
        "source": "iana",
        "compressible": true
    },
    "application/cbor": {
        "source": "iana"
    },
    "application/cbor-seq": {
        "source": "iana"
    },
    "application/cccex": {
        "source": "iana"
    },
    "application/ccmp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ccxml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ccxml"
        ]
    },
    "application/cdfx+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "cdfx"
        ]
    },
    "application/cdmi-capability": {
        "source": "iana",
        "extensions": [
            "cdmia"
        ]
    },
    "application/cdmi-container": {
        "source": "iana",
        "extensions": [
            "cdmic"
        ]
    },
    "application/cdmi-domain": {
        "source": "iana",
        "extensions": [
            "cdmid"
        ]
    },
    "application/cdmi-object": {
        "source": "iana",
        "extensions": [
            "cdmio"
        ]
    },
    "application/cdmi-queue": {
        "source": "iana",
        "extensions": [
            "cdmiq"
        ]
    },
    "application/cdni": {
        "source": "iana"
    },
    "application/cea": {
        "source": "iana"
    },
    "application/cea-2018+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cellml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cfw": {
        "source": "iana"
    },
    "application/city+json": {
        "source": "iana",
        "compressible": true
    },
    "application/clr": {
        "source": "iana"
    },
    "application/clue+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/clue_info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cms": {
        "source": "iana"
    },
    "application/cnrp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/coap-group+json": {
        "source": "iana",
        "compressible": true
    },
    "application/coap-payload": {
        "source": "iana"
    },
    "application/commonground": {
        "source": "iana"
    },
    "application/conference-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cose": {
        "source": "iana"
    },
    "application/cose-key": {
        "source": "iana"
    },
    "application/cose-key-set": {
        "source": "iana"
    },
    "application/cpl+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "cpl"
        ]
    },
    "application/csrattrs": {
        "source": "iana"
    },
    "application/csta+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cstadata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/csvm+json": {
        "source": "iana",
        "compressible": true
    },
    "application/cu-seeme": {
        "source": "apache",
        "extensions": [
            "cu"
        ]
    },
    "application/cwt": {
        "source": "iana"
    },
    "application/cybercash": {
        "source": "iana"
    },
    "application/dart": {
        "compressible": true
    },
    "application/dash+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpd"
        ]
    },
    "application/dash-patch+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpp"
        ]
    },
    "application/dashdelta": {
        "source": "iana"
    },
    "application/davmount+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "davmount"
        ]
    },
    "application/dca-rft": {
        "source": "iana"
    },
    "application/dcd": {
        "source": "iana"
    },
    "application/dec-dx": {
        "source": "iana"
    },
    "application/dialog-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/dicom": {
        "source": "iana"
    },
    "application/dicom+json": {
        "source": "iana",
        "compressible": true
    },
    "application/dicom+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/dii": {
        "source": "iana"
    },
    "application/dit": {
        "source": "iana"
    },
    "application/dns": {
        "source": "iana"
    },
    "application/dns+json": {
        "source": "iana",
        "compressible": true
    },
    "application/dns-message": {
        "source": "iana"
    },
    "application/docbook+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "dbk"
        ]
    },
    "application/dots+cbor": {
        "source": "iana"
    },
    "application/dskpp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/dssc+der": {
        "source": "iana",
        "extensions": [
            "dssc"
        ]
    },
    "application/dssc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xdssc"
        ]
    },
    "application/dvcs": {
        "source": "iana"
    },
    "application/ecmascript": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "es",
            "ecma"
        ]
    },
    "application/edi-consent": {
        "source": "iana"
    },
    "application/edi-x12": {
        "source": "iana",
        "compressible": false
    },
    "application/edifact": {
        "source": "iana",
        "compressible": false
    },
    "application/efi": {
        "source": "iana"
    },
    "application/elm+json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/elm+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.cap+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/emergencycalldata.comment+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.control+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.deviceinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.ecall.msd": {
        "source": "iana"
    },
    "application/emergencycalldata.providerinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.serviceinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.subscriberinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.veds+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emma+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "emma"
        ]
    },
    "application/emotionml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "emotionml"
        ]
    },
    "application/encaprtp": {
        "source": "iana"
    },
    "application/epp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/epub+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "epub"
        ]
    },
    "application/eshop": {
        "source": "iana"
    },
    "application/exi": {
        "source": "iana",
        "extensions": [
            "exi"
        ]
    },
    "application/expect-ct-report+json": {
        "source": "iana",
        "compressible": true
    },
    "application/express": {
        "source": "iana",
        "extensions": [
            "exp"
        ]
    },
    "application/fastinfoset": {
        "source": "iana"
    },
    "application/fastsoap": {
        "source": "iana"
    },
    "application/fdt+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "fdt"
        ]
    },
    "application/fhir+json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/fhir+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/fido.trusted-apps+json": {
        "compressible": true
    },
    "application/fits": {
        "source": "iana"
    },
    "application/flexfec": {
        "source": "iana"
    },
    "application/font-sfnt": {
        "source": "iana"
    },
    "application/font-tdpfr": {
        "source": "iana",
        "extensions": [
            "pfr"
        ]
    },
    "application/font-woff": {
        "source": "iana",
        "compressible": false
    },
    "application/framework-attributes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/geo+json": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "geojson"
        ]
    },
    "application/geo+json-seq": {
        "source": "iana"
    },
    "application/geopackage+sqlite3": {
        "source": "iana"
    },
    "application/geoxacml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/gltf-buffer": {
        "source": "iana"
    },
    "application/gml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "gml"
        ]
    },
    "application/gpx+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "gpx"
        ]
    },
    "application/gxf": {
        "source": "apache",
        "extensions": [
            "gxf"
        ]
    },
    "application/gzip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "gz"
        ]
    },
    "application/h224": {
        "source": "iana"
    },
    "application/held+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/hjson": {
        "extensions": [
            "hjson"
        ]
    },
    "application/http": {
        "source": "iana"
    },
    "application/hyperstudio": {
        "source": "iana",
        "extensions": [
            "stk"
        ]
    },
    "application/ibe-key-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ibe-pkg-reply+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ibe-pp-data": {
        "source": "iana"
    },
    "application/iges": {
        "source": "iana"
    },
    "application/im-iscomposing+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/index": {
        "source": "iana"
    },
    "application/index.cmd": {
        "source": "iana"
    },
    "application/index.obj": {
        "source": "iana"
    },
    "application/index.response": {
        "source": "iana"
    },
    "application/index.vnd": {
        "source": "iana"
    },
    "application/inkml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ink",
            "inkml"
        ]
    },
    "application/iotp": {
        "source": "iana"
    },
    "application/ipfix": {
        "source": "iana",
        "extensions": [
            "ipfix"
        ]
    },
    "application/ipp": {
        "source": "iana"
    },
    "application/isup": {
        "source": "iana"
    },
    "application/its+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "its"
        ]
    },
    "application/java-archive": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "jar",
            "war",
            "ear"
        ]
    },
    "application/java-serialized-object": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "ser"
        ]
    },
    "application/java-vm": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "class"
        ]
    },
    "application/javascript": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "js",
            "mjs"
        ]
    },
    "application/jf2feed+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jose": {
        "source": "iana"
    },
    "application/jose+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jrd+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jscalendar+json": {
        "source": "iana",
        "compressible": true
    },
    "application/json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "json",
            "map"
        ]
    },
    "application/json-patch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/json-seq": {
        "source": "iana"
    },
    "application/json5": {
        "extensions": [
            "json5"
        ]
    },
    "application/jsonml+json": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "jsonml"
        ]
    },
    "application/jwk+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jwk-set+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jwt": {
        "source": "iana"
    },
    "application/kpml-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/kpml-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ld+json": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "jsonld"
        ]
    },
    "application/lgr+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lgr"
        ]
    },
    "application/link-format": {
        "source": "iana"
    },
    "application/load-control+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/lost+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lostxml"
        ]
    },
    "application/lostsync+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/lpf+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/lxf": {
        "source": "iana"
    },
    "application/mac-binhex40": {
        "source": "iana",
        "extensions": [
            "hqx"
        ]
    },
    "application/mac-compactpro": {
        "source": "apache",
        "extensions": [
            "cpt"
        ]
    },
    "application/macwriteii": {
        "source": "iana"
    },
    "application/mads+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mads"
        ]
    },
    "application/manifest+json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "webmanifest"
        ]
    },
    "application/marc": {
        "source": "iana",
        "extensions": [
            "mrc"
        ]
    },
    "application/marcxml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mrcx"
        ]
    },
    "application/mathematica": {
        "source": "iana",
        "extensions": [
            "ma",
            "nb",
            "mb"
        ]
    },
    "application/mathml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mathml"
        ]
    },
    "application/mathml-content+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mathml-presentation+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-associated-procedure-description+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-deregister+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-envelope+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-msk+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-msk-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-protection-description+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-reception-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-register+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-register-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-schedule+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-user-service-description+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbox": {
        "source": "iana",
        "extensions": [
            "mbox"
        ]
    },
    "application/media-policy-dataset+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpf"
        ]
    },
    "application/media_control+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mediaservercontrol+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mscml"
        ]
    },
    "application/merge-patch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/metalink+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "metalink"
        ]
    },
    "application/metalink4+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "meta4"
        ]
    },
    "application/mets+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mets"
        ]
    },
    "application/mf4": {
        "source": "iana"
    },
    "application/mikey": {
        "source": "iana"
    },
    "application/mipc": {
        "source": "iana"
    },
    "application/missing-blocks+cbor-seq": {
        "source": "iana"
    },
    "application/mmt-aei+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "maei"
        ]
    },
    "application/mmt-usd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "musd"
        ]
    },
    "application/mods+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mods"
        ]
    },
    "application/moss-keys": {
        "source": "iana"
    },
    "application/moss-signature": {
        "source": "iana"
    },
    "application/mosskey-data": {
        "source": "iana"
    },
    "application/mosskey-request": {
        "source": "iana"
    },
    "application/mp21": {
        "source": "iana",
        "extensions": [
            "m21",
            "mp21"
        ]
    },
    "application/mp4": {
        "source": "iana",
        "extensions": [
            "mp4s",
            "m4p"
        ]
    },
    "application/mpeg4-generic": {
        "source": "iana"
    },
    "application/mpeg4-iod": {
        "source": "iana"
    },
    "application/mpeg4-iod-xmt": {
        "source": "iana"
    },
    "application/mrb-consumer+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mrb-publish+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/msc-ivr+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/msc-mixer+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/msword": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "doc",
            "dot"
        ]
    },
    "application/mud+json": {
        "source": "iana",
        "compressible": true
    },
    "application/multipart-core": {
        "source": "iana"
    },
    "application/mxf": {
        "source": "iana",
        "extensions": [
            "mxf"
        ]
    },
    "application/n-quads": {
        "source": "iana",
        "extensions": [
            "nq"
        ]
    },
    "application/n-triples": {
        "source": "iana",
        "extensions": [
            "nt"
        ]
    },
    "application/nasdata": {
        "source": "iana"
    },
    "application/news-checkgroups": {
        "source": "iana",
        "charset": "US-ASCII"
    },
    "application/news-groupinfo": {
        "source": "iana",
        "charset": "US-ASCII"
    },
    "application/news-transmission": {
        "source": "iana"
    },
    "application/nlsml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/node": {
        "source": "iana",
        "extensions": [
            "cjs"
        ]
    },
    "application/nss": {
        "source": "iana"
    },
    "application/oauth-authz-req+jwt": {
        "source": "iana"
    },
    "application/oblivious-dns-message": {
        "source": "iana"
    },
    "application/ocsp-request": {
        "source": "iana"
    },
    "application/ocsp-response": {
        "source": "iana"
    },
    "application/octet-stream": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "bin",
            "dms",
            "lrf",
            "mar",
            "so",
            "dist",
            "distz",
            "pkg",
            "bpk",
            "dump",
            "elc",
            "deploy",
            "exe",
            "dll",
            "deb",
            "dmg",
            "iso",
            "img",
            "msi",
            "msp",
            "msm",
            "buffer"
        ]
    },
    "application/oda": {
        "source": "iana",
        "extensions": [
            "oda"
        ]
    },
    "application/odm+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/odx": {
        "source": "iana"
    },
    "application/oebps-package+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "opf"
        ]
    },
    "application/ogg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ogx"
        ]
    },
    "application/omdoc+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "omdoc"
        ]
    },
    "application/onenote": {
        "source": "apache",
        "extensions": [
            "onetoc",
            "onetoc2",
            "onetmp",
            "onepkg"
        ]
    },
    "application/opc-nodeset+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/oscore": {
        "source": "iana"
    },
    "application/oxps": {
        "source": "iana",
        "extensions": [
            "oxps"
        ]
    },
    "application/p21": {
        "source": "iana"
    },
    "application/p21+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/p2p-overlay+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "relo"
        ]
    },
    "application/parityfec": {
        "source": "iana"
    },
    "application/passport": {
        "source": "iana"
    },
    "application/patch-ops-error+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xer"
        ]
    },
    "application/pdf": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "pdf"
        ]
    },
    "application/pdx": {
        "source": "iana"
    },
    "application/pem-certificate-chain": {
        "source": "iana"
    },
    "application/pgp-encrypted": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "pgp"
        ]
    },
    "application/pgp-keys": {
        "source": "iana",
        "extensions": [
            "asc"
        ]
    },
    "application/pgp-signature": {
        "source": "iana",
        "extensions": [
            "asc",
            "sig"
        ]
    },
    "application/pics-rules": {
        "source": "apache",
        "extensions": [
            "prf"
        ]
    },
    "application/pidf+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/pidf-diff+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/pkcs10": {
        "source": "iana",
        "extensions": [
            "p10"
        ]
    },
    "application/pkcs12": {
        "source": "iana"
    },
    "application/pkcs7-mime": {
        "source": "iana",
        "extensions": [
            "p7m",
            "p7c"
        ]
    },
    "application/pkcs7-signature": {
        "source": "iana",
        "extensions": [
            "p7s"
        ]
    },
    "application/pkcs8": {
        "source": "iana",
        "extensions": [
            "p8"
        ]
    },
    "application/pkcs8-encrypted": {
        "source": "iana"
    },
    "application/pkix-attr-cert": {
        "source": "iana",
        "extensions": [
            "ac"
        ]
    },
    "application/pkix-cert": {
        "source": "iana",
        "extensions": [
            "cer"
        ]
    },
    "application/pkix-crl": {
        "source": "iana",
        "extensions": [
            "crl"
        ]
    },
    "application/pkix-pkipath": {
        "source": "iana",
        "extensions": [
            "pkipath"
        ]
    },
    "application/pkixcmp": {
        "source": "iana",
        "extensions": [
            "pki"
        ]
    },
    "application/pls+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "pls"
        ]
    },
    "application/poc-settings+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/postscript": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ai",
            "eps",
            "ps"
        ]
    },
    "application/ppsp-tracker+json": {
        "source": "iana",
        "compressible": true
    },
    "application/problem+json": {
        "source": "iana",
        "compressible": true
    },
    "application/problem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/provenance+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "provx"
        ]
    },
    "application/prs.alvestrand.titrax-sheet": {
        "source": "iana"
    },
    "application/prs.cww": {
        "source": "iana",
        "extensions": [
            "cww"
        ]
    },
    "application/prs.cyn": {
        "source": "iana",
        "charset": "7-BIT"
    },
    "application/prs.hpub+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/prs.nprend": {
        "source": "iana"
    },
    "application/prs.plucker": {
        "source": "iana"
    },
    "application/prs.rdf-xml-crypt": {
        "source": "iana"
    },
    "application/prs.xsf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/pskc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "pskcxml"
        ]
    },
    "application/pvd+json": {
        "source": "iana",
        "compressible": true
    },
    "application/qsig": {
        "source": "iana"
    },
    "application/raml+yaml": {
        "compressible": true,
        "extensions": [
            "raml"
        ]
    },
    "application/raptorfec": {
        "source": "iana"
    },
    "application/rdap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/rdf+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rdf",
            "owl"
        ]
    },
    "application/reginfo+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rif"
        ]
    },
    "application/relax-ng-compact-syntax": {
        "source": "iana",
        "extensions": [
            "rnc"
        ]
    },
    "application/remote-printing": {
        "source": "iana"
    },
    "application/reputon+json": {
        "source": "iana",
        "compressible": true
    },
    "application/resource-lists+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rl"
        ]
    },
    "application/resource-lists-diff+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rld"
        ]
    },
    "application/rfc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/riscos": {
        "source": "iana"
    },
    "application/rlmi+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/rls-services+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rs"
        ]
    },
    "application/route-apd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rapd"
        ]
    },
    "application/route-s-tsid+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sls"
        ]
    },
    "application/route-usd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rusd"
        ]
    },
    "application/rpki-ghostbusters": {
        "source": "iana",
        "extensions": [
            "gbr"
        ]
    },
    "application/rpki-manifest": {
        "source": "iana",
        "extensions": [
            "mft"
        ]
    },
    "application/rpki-publication": {
        "source": "iana"
    },
    "application/rpki-roa": {
        "source": "iana",
        "extensions": [
            "roa"
        ]
    },
    "application/rpki-updown": {
        "source": "iana"
    },
    "application/rsd+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "rsd"
        ]
    },
    "application/rss+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "rss"
        ]
    },
    "application/rtf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rtf"
        ]
    },
    "application/rtploopback": {
        "source": "iana"
    },
    "application/rtx": {
        "source": "iana"
    },
    "application/samlassertion+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/samlmetadata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sarif+json": {
        "source": "iana",
        "compressible": true
    },
    "application/sarif-external-properties+json": {
        "source": "iana",
        "compressible": true
    },
    "application/sbe": {
        "source": "iana"
    },
    "application/sbml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sbml"
        ]
    },
    "application/scaip+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/scim+json": {
        "source": "iana",
        "compressible": true
    },
    "application/scvp-cv-request": {
        "source": "iana",
        "extensions": [
            "scq"
        ]
    },
    "application/scvp-cv-response": {
        "source": "iana",
        "extensions": [
            "scs"
        ]
    },
    "application/scvp-vp-request": {
        "source": "iana",
        "extensions": [
            "spq"
        ]
    },
    "application/scvp-vp-response": {
        "source": "iana",
        "extensions": [
            "spp"
        ]
    },
    "application/sdp": {
        "source": "iana",
        "extensions": [
            "sdp"
        ]
    },
    "application/secevent+jwt": {
        "source": "iana"
    },
    "application/senml+cbor": {
        "source": "iana"
    },
    "application/senml+json": {
        "source": "iana",
        "compressible": true
    },
    "application/senml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "senmlx"
        ]
    },
    "application/senml-etch+cbor": {
        "source": "iana"
    },
    "application/senml-etch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/senml-exi": {
        "source": "iana"
    },
    "application/sensml+cbor": {
        "source": "iana"
    },
    "application/sensml+json": {
        "source": "iana",
        "compressible": true
    },
    "application/sensml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sensmlx"
        ]
    },
    "application/sensml-exi": {
        "source": "iana"
    },
    "application/sep+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sep-exi": {
        "source": "iana"
    },
    "application/session-info": {
        "source": "iana"
    },
    "application/set-payment": {
        "source": "iana"
    },
    "application/set-payment-initiation": {
        "source": "iana",
        "extensions": [
            "setpay"
        ]
    },
    "application/set-registration": {
        "source": "iana"
    },
    "application/set-registration-initiation": {
        "source": "iana",
        "extensions": [
            "setreg"
        ]
    },
    "application/sgml": {
        "source": "iana"
    },
    "application/sgml-open-catalog": {
        "source": "iana"
    },
    "application/shf+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "shf"
        ]
    },
    "application/sieve": {
        "source": "iana",
        "extensions": [
            "siv",
            "sieve"
        ]
    },
    "application/simple-filter+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/simple-message-summary": {
        "source": "iana"
    },
    "application/simplesymbolcontainer": {
        "source": "iana"
    },
    "application/sipc": {
        "source": "iana"
    },
    "application/slate": {
        "source": "iana"
    },
    "application/smil": {
        "source": "iana"
    },
    "application/smil+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "smi",
            "smil"
        ]
    },
    "application/smpte336m": {
        "source": "iana"
    },
    "application/soap+fastinfoset": {
        "source": "iana"
    },
    "application/soap+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sparql-query": {
        "source": "iana",
        "extensions": [
            "rq"
        ]
    },
    "application/sparql-results+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "srx"
        ]
    },
    "application/spdx+json": {
        "source": "iana",
        "compressible": true
    },
    "application/spirits-event+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sql": {
        "source": "iana"
    },
    "application/srgs": {
        "source": "iana",
        "extensions": [
            "gram"
        ]
    },
    "application/srgs+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "grxml"
        ]
    },
    "application/sru+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sru"
        ]
    },
    "application/ssdl+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "ssdl"
        ]
    },
    "application/ssml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ssml"
        ]
    },
    "application/stix+json": {
        "source": "iana",
        "compressible": true
    },
    "application/swid+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "swidtag"
        ]
    },
    "application/tamp-apex-update": {
        "source": "iana"
    },
    "application/tamp-apex-update-confirm": {
        "source": "iana"
    },
    "application/tamp-community-update": {
        "source": "iana"
    },
    "application/tamp-community-update-confirm": {
        "source": "iana"
    },
    "application/tamp-error": {
        "source": "iana"
    },
    "application/tamp-sequence-adjust": {
        "source": "iana"
    },
    "application/tamp-sequence-adjust-confirm": {
        "source": "iana"
    },
    "application/tamp-status-query": {
        "source": "iana"
    },
    "application/tamp-status-response": {
        "source": "iana"
    },
    "application/tamp-update": {
        "source": "iana"
    },
    "application/tamp-update-confirm": {
        "source": "iana"
    },
    "application/tar": {
        "compressible": true
    },
    "application/taxii+json": {
        "source": "iana",
        "compressible": true
    },
    "application/td+json": {
        "source": "iana",
        "compressible": true
    },
    "application/tei+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "tei",
            "teicorpus"
        ]
    },
    "application/tetra_isi": {
        "source": "iana"
    },
    "application/thraud+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "tfi"
        ]
    },
    "application/timestamp-query": {
        "source": "iana"
    },
    "application/timestamp-reply": {
        "source": "iana"
    },
    "application/timestamped-data": {
        "source": "iana",
        "extensions": [
            "tsd"
        ]
    },
    "application/tlsrpt+gzip": {
        "source": "iana"
    },
    "application/tlsrpt+json": {
        "source": "iana",
        "compressible": true
    },
    "application/tnauthlist": {
        "source": "iana"
    },
    "application/token-introspection+jwt": {
        "source": "iana"
    },
    "application/toml": {
        "compressible": true,
        "extensions": [
            "toml"
        ]
    },
    "application/trickle-ice-sdpfrag": {
        "source": "iana"
    },
    "application/trig": {
        "source": "iana",
        "extensions": [
            "trig"
        ]
    },
    "application/ttml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ttml"
        ]
    },
    "application/tve-trigger": {
        "source": "iana"
    },
    "application/tzif": {
        "source": "iana"
    },
    "application/tzif-leap": {
        "source": "iana"
    },
    "application/ubjson": {
        "compressible": false,
        "extensions": [
            "ubj"
        ]
    },
    "application/ulpfec": {
        "source": "iana"
    },
    "application/urc-grpsheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/urc-ressheet+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rsheet"
        ]
    },
    "application/urc-targetdesc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "td"
        ]
    },
    "application/urc-uisocketdesc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vcard+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vcard+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vemmi": {
        "source": "iana"
    },
    "application/vividence.scriptfile": {
        "source": "apache"
    },
    "application/vnd.1000minds.decision-model+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "1km"
        ]
    },
    "application/vnd.3gpp-prose+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp-prose-pc3ch+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp-v2x-local-service-information": {
        "source": "iana"
    },
    "application/vnd.3gpp.5gnas": {
        "source": "iana"
    },
    "application/vnd.3gpp.access-transfer-events+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.bsf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.gmop+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.gtpc": {
        "source": "iana"
    },
    "application/vnd.3gpp.interworking-data": {
        "source": "iana"
    },
    "application/vnd.3gpp.lpp": {
        "source": "iana"
    },
    "application/vnd.3gpp.mc-signalling-ear": {
        "source": "iana"
    },
    "application/vnd.3gpp.mcdata-affiliation-command+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-payload": {
        "source": "iana"
    },
    "application/vnd.3gpp.mcdata-service-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-signalling": {
        "source": "iana"
    },
    "application/vnd.3gpp.mcdata-ue-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-user-profile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-affiliation-command+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-floor-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-location-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-mbms-usage-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-service-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-signed+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-ue-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-ue-init-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-user-profile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-affiliation-command+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-affiliation-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-location-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-mbms-usage-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-service-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-transmission-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-ue-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-user-profile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mid-call+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.ngap": {
        "source": "iana"
    },
    "application/vnd.3gpp.pfcp": {
        "source": "iana"
    },
    "application/vnd.3gpp.pic-bw-large": {
        "source": "iana",
        "extensions": [
            "plb"
        ]
    },
    "application/vnd.3gpp.pic-bw-small": {
        "source": "iana",
        "extensions": [
            "psb"
        ]
    },
    "application/vnd.3gpp.pic-bw-var": {
        "source": "iana",
        "extensions": [
            "pvb"
        ]
    },
    "application/vnd.3gpp.s1ap": {
        "source": "iana"
    },
    "application/vnd.3gpp.sms": {
        "source": "iana"
    },
    "application/vnd.3gpp.sms+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.srvcc-ext+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.srvcc-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.state-and-event-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.ussd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp2.bcmcsinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp2.sms": {
        "source": "iana"
    },
    "application/vnd.3gpp2.tcap": {
        "source": "iana",
        "extensions": [
            "tcap"
        ]
    },
    "application/vnd.3lightssoftware.imagescal": {
        "source": "iana"
    },
    "application/vnd.3m.post-it-notes": {
        "source": "iana",
        "extensions": [
            "pwn"
        ]
    },
    "application/vnd.accpac.simply.aso": {
        "source": "iana",
        "extensions": [
            "aso"
        ]
    },
    "application/vnd.accpac.simply.imp": {
        "source": "iana",
        "extensions": [
            "imp"
        ]
    },
    "application/vnd.acucobol": {
        "source": "iana",
        "extensions": [
            "acu"
        ]
    },
    "application/vnd.acucorp": {
        "source": "iana",
        "extensions": [
            "atc",
            "acutc"
        ]
    },
    "application/vnd.adobe.air-application-installer-package+zip": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "air"
        ]
    },
    "application/vnd.adobe.flash.movie": {
        "source": "iana"
    },
    "application/vnd.adobe.formscentral.fcdt": {
        "source": "iana",
        "extensions": [
            "fcdt"
        ]
    },
    "application/vnd.adobe.fxp": {
        "source": "iana",
        "extensions": [
            "fxp",
            "fxpl"
        ]
    },
    "application/vnd.adobe.partial-upload": {
        "source": "iana"
    },
    "application/vnd.adobe.xdp+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xdp"
        ]
    },
    "application/vnd.adobe.xfdf": {
        "source": "iana",
        "extensions": [
            "xfdf"
        ]
    },
    "application/vnd.aether.imp": {
        "source": "iana"
    },
    "application/vnd.afpc.afplinedata": {
        "source": "iana"
    },
    "application/vnd.afpc.afplinedata-pagedef": {
        "source": "iana"
    },
    "application/vnd.afpc.cmoca-cmresource": {
        "source": "iana"
    },
    "application/vnd.afpc.foca-charset": {
        "source": "iana"
    },
    "application/vnd.afpc.foca-codedfont": {
        "source": "iana"
    },
    "application/vnd.afpc.foca-codepage": {
        "source": "iana"
    },
    "application/vnd.afpc.modca": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-cmtable": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-formdef": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-mediummap": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-objectcontainer": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-overlay": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-pagesegment": {
        "source": "iana"
    },
    "application/vnd.age": {
        "source": "iana",
        "extensions": [
            "age"
        ]
    },
    "application/vnd.ah-barcode": {
        "source": "iana"
    },
    "application/vnd.ahead.space": {
        "source": "iana",
        "extensions": [
            "ahead"
        ]
    },
    "application/vnd.airzip.filesecure.azf": {
        "source": "iana",
        "extensions": [
            "azf"
        ]
    },
    "application/vnd.airzip.filesecure.azs": {
        "source": "iana",
        "extensions": [
            "azs"
        ]
    },
    "application/vnd.amadeus+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.amazon.ebook": {
        "source": "apache",
        "extensions": [
            "azw"
        ]
    },
    "application/vnd.amazon.mobi8-ebook": {
        "source": "iana"
    },
    "application/vnd.americandynamics.acc": {
        "source": "iana",
        "extensions": [
            "acc"
        ]
    },
    "application/vnd.amiga.ami": {
        "source": "iana",
        "extensions": [
            "ami"
        ]
    },
    "application/vnd.amundsen.maze+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.android.ota": {
        "source": "iana"
    },
    "application/vnd.android.package-archive": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "apk"
        ]
    },
    "application/vnd.anki": {
        "source": "iana"
    },
    "application/vnd.anser-web-certificate-issue-initiation": {
        "source": "iana",
        "extensions": [
            "cii"
        ]
    },
    "application/vnd.anser-web-funds-transfer-initiation": {
        "source": "apache",
        "extensions": [
            "fti"
        ]
    },
    "application/vnd.antix.game-component": {
        "source": "iana",
        "extensions": [
            "atx"
        ]
    },
    "application/vnd.apache.arrow.file": {
        "source": "iana"
    },
    "application/vnd.apache.arrow.stream": {
        "source": "iana"
    },
    "application/vnd.apache.thrift.binary": {
        "source": "iana"
    },
    "application/vnd.apache.thrift.compact": {
        "source": "iana"
    },
    "application/vnd.apache.thrift.json": {
        "source": "iana"
    },
    "application/vnd.api+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.aplextor.warrp+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.apothekende.reservation+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.apple.installer+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpkg"
        ]
    },
    "application/vnd.apple.keynote": {
        "source": "iana",
        "extensions": [
            "key"
        ]
    },
    "application/vnd.apple.mpegurl": {
        "source": "iana",
        "extensions": [
            "m3u8"
        ]
    },
    "application/vnd.apple.numbers": {
        "source": "iana",
        "extensions": [
            "numbers"
        ]
    },
    "application/vnd.apple.pages": {
        "source": "iana",
        "extensions": [
            "pages"
        ]
    },
    "application/vnd.apple.pkpass": {
        "compressible": false,
        "extensions": [
            "pkpass"
        ]
    },
    "application/vnd.arastra.swi": {
        "source": "iana"
    },
    "application/vnd.aristanetworks.swi": {
        "source": "iana",
        "extensions": [
            "swi"
        ]
    },
    "application/vnd.artisan+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.artsquare": {
        "source": "iana"
    },
    "application/vnd.astraea-software.iota": {
        "source": "iana",
        "extensions": [
            "iota"
        ]
    },
    "application/vnd.audiograph": {
        "source": "iana",
        "extensions": [
            "aep"
        ]
    },
    "application/vnd.autopackage": {
        "source": "iana"
    },
    "application/vnd.avalon+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.avistar+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.balsamiq.bmml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "bmml"
        ]
    },
    "application/vnd.balsamiq.bmpr": {
        "source": "iana"
    },
    "application/vnd.banana-accounting": {
        "source": "iana"
    },
    "application/vnd.bbf.usp.error": {
        "source": "iana"
    },
    "application/vnd.bbf.usp.msg": {
        "source": "iana"
    },
    "application/vnd.bbf.usp.msg+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.bekitzur-stech+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.bint.med-content": {
        "source": "iana"
    },
    "application/vnd.biopax.rdf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.blink-idb-value-wrapper": {
        "source": "iana"
    },
    "application/vnd.blueice.multipass": {
        "source": "iana",
        "extensions": [
            "mpm"
        ]
    },
    "application/vnd.bluetooth.ep.oob": {
        "source": "iana"
    },
    "application/vnd.bluetooth.le.oob": {
        "source": "iana"
    },
    "application/vnd.bmi": {
        "source": "iana",
        "extensions": [
            "bmi"
        ]
    },
    "application/vnd.bpf": {
        "source": "iana"
    },
    "application/vnd.bpf3": {
        "source": "iana"
    },
    "application/vnd.businessobjects": {
        "source": "iana",
        "extensions": [
            "rep"
        ]
    },
    "application/vnd.byu.uapi+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cab-jscript": {
        "source": "iana"
    },
    "application/vnd.canon-cpdl": {
        "source": "iana"
    },
    "application/vnd.canon-lips": {
        "source": "iana"
    },
    "application/vnd.capasystems-pg+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cendio.thinlinc.clientconf": {
        "source": "iana"
    },
    "application/vnd.century-systems.tcp_stream": {
        "source": "iana"
    },
    "application/vnd.chemdraw+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "cdxml"
        ]
    },
    "application/vnd.chess-pgn": {
        "source": "iana"
    },
    "application/vnd.chipnuts.karaoke-mmd": {
        "source": "iana",
        "extensions": [
            "mmd"
        ]
    },
    "application/vnd.ciedi": {
        "source": "iana"
    },
    "application/vnd.cinderella": {
        "source": "iana",
        "extensions": [
            "cdy"
        ]
    },
    "application/vnd.cirpack.isdn-ext": {
        "source": "iana"
    },
    "application/vnd.citationstyles.style+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "csl"
        ]
    },
    "application/vnd.claymore": {
        "source": "iana",
        "extensions": [
            "cla"
        ]
    },
    "application/vnd.cloanto.rp9": {
        "source": "iana",
        "extensions": [
            "rp9"
        ]
    },
    "application/vnd.clonk.c4group": {
        "source": "iana",
        "extensions": [
            "c4g",
            "c4d",
            "c4f",
            "c4p",
            "c4u"
        ]
    },
    "application/vnd.cluetrust.cartomobile-config": {
        "source": "iana",
        "extensions": [
            "c11amc"
        ]
    },
    "application/vnd.cluetrust.cartomobile-config-pkg": {
        "source": "iana",
        "extensions": [
            "c11amz"
        ]
    },
    "application/vnd.coffeescript": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.document": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.document-template": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.presentation": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.presentation-template": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.spreadsheet": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.spreadsheet-template": {
        "source": "iana"
    },
    "application/vnd.collection+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.collection.doc+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.collection.next+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.comicbook+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.comicbook-rar": {
        "source": "iana"
    },
    "application/vnd.commerce-battelle": {
        "source": "iana"
    },
    "application/vnd.commonspace": {
        "source": "iana",
        "extensions": [
            "csp"
        ]
    },
    "application/vnd.contact.cmsg": {
        "source": "iana",
        "extensions": [
            "cdbcmsg"
        ]
    },
    "application/vnd.coreos.ignition+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cosmocaller": {
        "source": "iana",
        "extensions": [
            "cmc"
        ]
    },
    "application/vnd.crick.clicker": {
        "source": "iana",
        "extensions": [
            "clkx"
        ]
    },
    "application/vnd.crick.clicker.keyboard": {
        "source": "iana",
        "extensions": [
            "clkk"
        ]
    },
    "application/vnd.crick.clicker.palette": {
        "source": "iana",
        "extensions": [
            "clkp"
        ]
    },
    "application/vnd.crick.clicker.template": {
        "source": "iana",
        "extensions": [
            "clkt"
        ]
    },
    "application/vnd.crick.clicker.wordbank": {
        "source": "iana",
        "extensions": [
            "clkw"
        ]
    },
    "application/vnd.criticaltools.wbs+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wbs"
        ]
    },
    "application/vnd.cryptii.pipe+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.crypto-shade-file": {
        "source": "iana"
    },
    "application/vnd.cryptomator.encrypted": {
        "source": "iana"
    },
    "application/vnd.cryptomator.vault": {
        "source": "iana"
    },
    "application/vnd.ctc-posml": {
        "source": "iana",
        "extensions": [
            "pml"
        ]
    },
    "application/vnd.ctct.ws+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cups-pdf": {
        "source": "iana"
    },
    "application/vnd.cups-postscript": {
        "source": "iana"
    },
    "application/vnd.cups-ppd": {
        "source": "iana",
        "extensions": [
            "ppd"
        ]
    },
    "application/vnd.cups-raster": {
        "source": "iana"
    },
    "application/vnd.cups-raw": {
        "source": "iana"
    },
    "application/vnd.curl": {
        "source": "iana"
    },
    "application/vnd.curl.car": {
        "source": "apache",
        "extensions": [
            "car"
        ]
    },
    "application/vnd.curl.pcurl": {
        "source": "apache",
        "extensions": [
            "pcurl"
        ]
    },
    "application/vnd.cyan.dean.root+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cybank": {
        "source": "iana"
    },
    "application/vnd.cyclonedx+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cyclonedx+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.d2l.coursepackage1p0+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.d3m-dataset": {
        "source": "iana"
    },
    "application/vnd.d3m-problem": {
        "source": "iana"
    },
    "application/vnd.dart": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dart"
        ]
    },
    "application/vnd.data-vision.rdz": {
        "source": "iana",
        "extensions": [
            "rdz"
        ]
    },
    "application/vnd.datapackage+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dataresource+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dbf": {
        "source": "iana",
        "extensions": [
            "dbf"
        ]
    },
    "application/vnd.debian.binary-package": {
        "source": "iana"
    },
    "application/vnd.dece.data": {
        "source": "iana",
        "extensions": [
            "uvf",
            "uvvf",
            "uvd",
            "uvvd"
        ]
    },
    "application/vnd.dece.ttml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "uvt",
            "uvvt"
        ]
    },
    "application/vnd.dece.unspecified": {
        "source": "iana",
        "extensions": [
            "uvx",
            "uvvx"
        ]
    },
    "application/vnd.dece.zip": {
        "source": "iana",
        "extensions": [
            "uvz",
            "uvvz"
        ]
    },
    "application/vnd.denovo.fcselayout-link": {
        "source": "iana",
        "extensions": [
            "fe_launch"
        ]
    },
    "application/vnd.desmume.movie": {
        "source": "iana"
    },
    "application/vnd.dir-bi.plate-dl-nosuffix": {
        "source": "iana"
    },
    "application/vnd.dm.delegation+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dna": {
        "source": "iana",
        "extensions": [
            "dna"
        ]
    },
    "application/vnd.document+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dolby.mlp": {
        "source": "apache",
        "extensions": [
            "mlp"
        ]
    },
    "application/vnd.dolby.mobile.1": {
        "source": "iana"
    },
    "application/vnd.dolby.mobile.2": {
        "source": "iana"
    },
    "application/vnd.doremir.scorecloud-binary-document": {
        "source": "iana"
    },
    "application/vnd.dpgraph": {
        "source": "iana",
        "extensions": [
            "dpg"
        ]
    },
    "application/vnd.dreamfactory": {
        "source": "iana",
        "extensions": [
            "dfac"
        ]
    },
    "application/vnd.drive+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ds-keypoint": {
        "source": "apache",
        "extensions": [
            "kpxx"
        ]
    },
    "application/vnd.dtg.local": {
        "source": "iana"
    },
    "application/vnd.dtg.local.flash": {
        "source": "iana"
    },
    "application/vnd.dtg.local.html": {
        "source": "iana"
    },
    "application/vnd.dvb.ait": {
        "source": "iana",
        "extensions": [
            "ait"
        ]
    },
    "application/vnd.dvb.dvbisl+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.dvbj": {
        "source": "iana"
    },
    "application/vnd.dvb.esgcontainer": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcdftnotifaccess": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcesgaccess": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcesgaccess2": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcesgpdd": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcroaming": {
        "source": "iana"
    },
    "application/vnd.dvb.iptv.alfec-base": {
        "source": "iana"
    },
    "application/vnd.dvb.iptv.alfec-enhancement": {
        "source": "iana"
    },
    "application/vnd.dvb.notif-aggregate-root+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-container+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-generic+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-ia-msglist+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-ia-registration-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-ia-registration-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-init+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.pfr": {
        "source": "iana"
    },
    "application/vnd.dvb.service": {
        "source": "iana",
        "extensions": [
            "svc"
        ]
    },
    "application/vnd.dxr": {
        "source": "iana"
    },
    "application/vnd.dynageo": {
        "source": "iana",
        "extensions": [
            "geo"
        ]
    },
    "application/vnd.dzr": {
        "source": "iana"
    },
    "application/vnd.easykaraoke.cdgdownload": {
        "source": "iana"
    },
    "application/vnd.ecdis-update": {
        "source": "iana"
    },
    "application/vnd.ecip.rlp": {
        "source": "iana"
    },
    "application/vnd.eclipse.ditto+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ecowin.chart": {
        "source": "iana",
        "extensions": [
            "mag"
        ]
    },
    "application/vnd.ecowin.filerequest": {
        "source": "iana"
    },
    "application/vnd.ecowin.fileupdate": {
        "source": "iana"
    },
    "application/vnd.ecowin.series": {
        "source": "iana"
    },
    "application/vnd.ecowin.seriesrequest": {
        "source": "iana"
    },
    "application/vnd.ecowin.seriesupdate": {
        "source": "iana"
    },
    "application/vnd.efi.img": {
        "source": "iana"
    },
    "application/vnd.efi.iso": {
        "source": "iana"
    },
    "application/vnd.emclient.accessrequest+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.enliven": {
        "source": "iana",
        "extensions": [
            "nml"
        ]
    },
    "application/vnd.enphase.envoy": {
        "source": "iana"
    },
    "application/vnd.eprints.data+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.epson.esf": {
        "source": "iana",
        "extensions": [
            "esf"
        ]
    },
    "application/vnd.epson.msf": {
        "source": "iana",
        "extensions": [
            "msf"
        ]
    },
    "application/vnd.epson.quickanime": {
        "source": "iana",
        "extensions": [
            "qam"
        ]
    },
    "application/vnd.epson.salt": {
        "source": "iana",
        "extensions": [
            "slt"
        ]
    },
    "application/vnd.epson.ssf": {
        "source": "iana",
        "extensions": [
            "ssf"
        ]
    },
    "application/vnd.ericsson.quickcall": {
        "source": "iana"
    },
    "application/vnd.espass-espass+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.eszigno3+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "es3",
            "et3"
        ]
    },
    "application/vnd.etsi.aoc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.asic-e+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.etsi.asic-s+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.etsi.cug+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvcommand+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvdiscovery+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsad-bc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsad-cod+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsad-npvr+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvservice+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsync+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvueprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.mcid+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.mheg5": {
        "source": "iana"
    },
    "application/vnd.etsi.overload-control-policy-dataset+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.pstn+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.sci+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.simservs+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.timestamp-token": {
        "source": "iana"
    },
    "application/vnd.etsi.tsl+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.tsl.der": {
        "source": "iana"
    },
    "application/vnd.eu.kasparian.car+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.eudora.data": {
        "source": "iana"
    },
    "application/vnd.evolv.ecig.profile": {
        "source": "iana"
    },
    "application/vnd.evolv.ecig.settings": {
        "source": "iana"
    },
    "application/vnd.evolv.ecig.theme": {
        "source": "iana"
    },
    "application/vnd.exstream-empower+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.exstream-package": {
        "source": "iana"
    },
    "application/vnd.ezpix-album": {
        "source": "iana",
        "extensions": [
            "ez2"
        ]
    },
    "application/vnd.ezpix-package": {
        "source": "iana",
        "extensions": [
            "ez3"
        ]
    },
    "application/vnd.f-secure.mobile": {
        "source": "iana"
    },
    "application/vnd.familysearch.gedcom+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.fastcopy-disk-image": {
        "source": "iana"
    },
    "application/vnd.fdf": {
        "source": "iana",
        "extensions": [
            "fdf"
        ]
    },
    "application/vnd.fdsn.mseed": {
        "source": "iana",
        "extensions": [
            "mseed"
        ]
    },
    "application/vnd.fdsn.seed": {
        "source": "iana",
        "extensions": [
            "seed",
            "dataless"
        ]
    },
    "application/vnd.ffsns": {
        "source": "iana"
    },
    "application/vnd.ficlab.flb+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.filmit.zfc": {
        "source": "iana"
    },
    "application/vnd.fints": {
        "source": "iana"
    },
    "application/vnd.firemonkeys.cloudcell": {
        "source": "iana"
    },
    "application/vnd.flographit": {
        "source": "iana",
        "extensions": [
            "gph"
        ]
    },
    "application/vnd.fluxtime.clip": {
        "source": "iana",
        "extensions": [
            "ftc"
        ]
    },
    "application/vnd.font-fontforge-sfd": {
        "source": "iana"
    },
    "application/vnd.framemaker": {
        "source": "iana",
        "extensions": [
            "fm",
            "frame",
            "maker",
            "book"
        ]
    },
    "application/vnd.frogans.fnc": {
        "source": "iana",
        "extensions": [
            "fnc"
        ]
    },
    "application/vnd.frogans.ltf": {
        "source": "iana",
        "extensions": [
            "ltf"
        ]
    },
    "application/vnd.fsc.weblaunch": {
        "source": "iana",
        "extensions": [
            "fsc"
        ]
    },
    "application/vnd.fujifilm.fb.docuworks": {
        "source": "iana"
    },
    "application/vnd.fujifilm.fb.docuworks.binder": {
        "source": "iana"
    },
    "application/vnd.fujifilm.fb.docuworks.container": {
        "source": "iana"
    },
    "application/vnd.fujifilm.fb.jfi+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.fujitsu.oasys": {
        "source": "iana",
        "extensions": [
            "oas"
        ]
    },
    "application/vnd.fujitsu.oasys2": {
        "source": "iana",
        "extensions": [
            "oa2"
        ]
    },
    "application/vnd.fujitsu.oasys3": {
        "source": "iana",
        "extensions": [
            "oa3"
        ]
    },
    "application/vnd.fujitsu.oasysgp": {
        "source": "iana",
        "extensions": [
            "fg5"
        ]
    },
    "application/vnd.fujitsu.oasysprs": {
        "source": "iana",
        "extensions": [
            "bh2"
        ]
    },
    "application/vnd.fujixerox.art-ex": {
        "source": "iana"
    },
    "application/vnd.fujixerox.art4": {
        "source": "iana"
    },
    "application/vnd.fujixerox.ddd": {
        "source": "iana",
        "extensions": [
            "ddd"
        ]
    },
    "application/vnd.fujixerox.docuworks": {
        "source": "iana",
        "extensions": [
            "xdw"
        ]
    },
    "application/vnd.fujixerox.docuworks.binder": {
        "source": "iana",
        "extensions": [
            "xbd"
        ]
    },
    "application/vnd.fujixerox.docuworks.container": {
        "source": "iana"
    },
    "application/vnd.fujixerox.hbpl": {
        "source": "iana"
    },
    "application/vnd.fut-misnet": {
        "source": "iana"
    },
    "application/vnd.futoin+cbor": {
        "source": "iana"
    },
    "application/vnd.futoin+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.fuzzysheet": {
        "source": "iana",
        "extensions": [
            "fzs"
        ]
    },
    "application/vnd.genomatix.tuxedo": {
        "source": "iana",
        "extensions": [
            "txd"
        ]
    },
    "application/vnd.gentics.grd+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.geo+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.geocube+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.geogebra.file": {
        "source": "iana",
        "extensions": [
            "ggb"
        ]
    },
    "application/vnd.geogebra.slides": {
        "source": "iana"
    },
    "application/vnd.geogebra.tool": {
        "source": "iana",
        "extensions": [
            "ggt"
        ]
    },
    "application/vnd.geometry-explorer": {
        "source": "iana",
        "extensions": [
            "gex",
            "gre"
        ]
    },
    "application/vnd.geonext": {
        "source": "iana",
        "extensions": [
            "gxt"
        ]
    },
    "application/vnd.geoplan": {
        "source": "iana",
        "extensions": [
            "g2w"
        ]
    },
    "application/vnd.geospace": {
        "source": "iana",
        "extensions": [
            "g3w"
        ]
    },
    "application/vnd.gerber": {
        "source": "iana"
    },
    "application/vnd.globalplatform.card-content-mgt": {
        "source": "iana"
    },
    "application/vnd.globalplatform.card-content-mgt-response": {
        "source": "iana"
    },
    "application/vnd.gmx": {
        "source": "iana",
        "extensions": [
            "gmx"
        ]
    },
    "application/vnd.google-apps.document": {
        "compressible": false,
        "extensions": [
            "gdoc"
        ]
    },
    "application/vnd.google-apps.presentation": {
        "compressible": false,
        "extensions": [
            "gslides"
        ]
    },
    "application/vnd.google-apps.spreadsheet": {
        "compressible": false,
        "extensions": [
            "gsheet"
        ]
    },
    "application/vnd.google-earth.kml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "kml"
        ]
    },
    "application/vnd.google-earth.kmz": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "kmz"
        ]
    },
    "application/vnd.gov.sk.e-form+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.gov.sk.e-form+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.gov.sk.xmldatacontainer+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.grafeq": {
        "source": "iana",
        "extensions": [
            "gqf",
            "gqs"
        ]
    },
    "application/vnd.gridmp": {
        "source": "iana"
    },
    "application/vnd.groove-account": {
        "source": "iana",
        "extensions": [
            "gac"
        ]
    },
    "application/vnd.groove-help": {
        "source": "iana",
        "extensions": [
            "ghf"
        ]
    },
    "application/vnd.groove-identity-message": {
        "source": "iana",
        "extensions": [
            "gim"
        ]
    },
    "application/vnd.groove-injector": {
        "source": "iana",
        "extensions": [
            "grv"
        ]
    },
    "application/vnd.groove-tool-message": {
        "source": "iana",
        "extensions": [
            "gtm"
        ]
    },
    "application/vnd.groove-tool-template": {
        "source": "iana",
        "extensions": [
            "tpl"
        ]
    },
    "application/vnd.groove-vcard": {
        "source": "iana",
        "extensions": [
            "vcg"
        ]
    },
    "application/vnd.hal+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hal+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "hal"
        ]
    },
    "application/vnd.handheld-entertainment+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "zmm"
        ]
    },
    "application/vnd.hbci": {
        "source": "iana",
        "extensions": [
            "hbci"
        ]
    },
    "application/vnd.hc+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hcl-bireports": {
        "source": "iana"
    },
    "application/vnd.hdt": {
        "source": "iana"
    },
    "application/vnd.heroku+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hhe.lesson-player": {
        "source": "iana",
        "extensions": [
            "les"
        ]
    },
    "application/vnd.hl7cda+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.hl7v2+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.hp-hpgl": {
        "source": "iana",
        "extensions": [
            "hpgl"
        ]
    },
    "application/vnd.hp-hpid": {
        "source": "iana",
        "extensions": [
            "hpid"
        ]
    },
    "application/vnd.hp-hps": {
        "source": "iana",
        "extensions": [
            "hps"
        ]
    },
    "application/vnd.hp-jlyt": {
        "source": "iana",
        "extensions": [
            "jlt"
        ]
    },
    "application/vnd.hp-pcl": {
        "source": "iana",
        "extensions": [
            "pcl"
        ]
    },
    "application/vnd.hp-pclxl": {
        "source": "iana",
        "extensions": [
            "pclxl"
        ]
    },
    "application/vnd.httphone": {
        "source": "iana"
    },
    "application/vnd.hydrostatix.sof-data": {
        "source": "iana",
        "extensions": [
            "sfd-hdstx"
        ]
    },
    "application/vnd.hyper+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hyper-item+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hyperdrive+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hzn-3d-crossword": {
        "source": "iana"
    },
    "application/vnd.ibm.afplinedata": {
        "source": "iana"
    },
    "application/vnd.ibm.electronic-media": {
        "source": "iana"
    },
    "application/vnd.ibm.minipay": {
        "source": "iana",
        "extensions": [
            "mpy"
        ]
    },
    "application/vnd.ibm.modcap": {
        "source": "iana",
        "extensions": [
            "afp",
            "listafp",
            "list3820"
        ]
    },
    "application/vnd.ibm.rights-management": {
        "source": "iana",
        "extensions": [
            "irm"
        ]
    },
    "application/vnd.ibm.secure-container": {
        "source": "iana",
        "extensions": [
            "sc"
        ]
    },
    "application/vnd.iccprofile": {
        "source": "iana",
        "extensions": [
            "icc",
            "icm"
        ]
    },
    "application/vnd.ieee.1905": {
        "source": "iana"
    },
    "application/vnd.igloader": {
        "source": "iana",
        "extensions": [
            "igl"
        ]
    },
    "application/vnd.imagemeter.folder+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.imagemeter.image+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.immervision-ivp": {
        "source": "iana",
        "extensions": [
            "ivp"
        ]
    },
    "application/vnd.immervision-ivu": {
        "source": "iana",
        "extensions": [
            "ivu"
        ]
    },
    "application/vnd.ims.imsccv1p1": {
        "source": "iana"
    },
    "application/vnd.ims.imsccv1p2": {
        "source": "iana"
    },
    "application/vnd.ims.imsccv1p3": {
        "source": "iana"
    },
    "application/vnd.ims.lis.v2.result+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolconsumerprofile+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolproxy+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolproxy.id+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolsettings+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolsettings.simple+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.informedcontrol.rms+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.informix-visionary": {
        "source": "iana"
    },
    "application/vnd.infotech.project": {
        "source": "iana"
    },
    "application/vnd.infotech.project+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.innopath.wamp.notification": {
        "source": "iana"
    },
    "application/vnd.insors.igm": {
        "source": "iana",
        "extensions": [
            "igm"
        ]
    },
    "application/vnd.intercon.formnet": {
        "source": "iana",
        "extensions": [
            "xpw",
            "xpx"
        ]
    },
    "application/vnd.intergeo": {
        "source": "iana",
        "extensions": [
            "i2g"
        ]
    },
    "application/vnd.intertrust.digibox": {
        "source": "iana"
    },
    "application/vnd.intertrust.nncp": {
        "source": "iana"
    },
    "application/vnd.intu.qbo": {
        "source": "iana",
        "extensions": [
            "qbo"
        ]
    },
    "application/vnd.intu.qfx": {
        "source": "iana",
        "extensions": [
            "qfx"
        ]
    },
    "application/vnd.iptc.g2.catalogitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.conceptitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.knowledgeitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.newsitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.newsmessage+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.packageitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.planningitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ipunplugged.rcprofile": {
        "source": "iana",
        "extensions": [
            "rcprofile"
        ]
    },
    "application/vnd.irepository.package+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "irp"
        ]
    },
    "application/vnd.is-xpr": {
        "source": "iana",
        "extensions": [
            "xpr"
        ]
    },
    "application/vnd.isac.fcs": {
        "source": "iana",
        "extensions": [
            "fcs"
        ]
    },
    "application/vnd.iso11783-10+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.jam": {
        "source": "iana",
        "extensions": [
            "jam"
        ]
    },
    "application/vnd.japannet-directory-service": {
        "source": "iana"
    },
    "application/vnd.japannet-jpnstore-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-payment-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-registration": {
        "source": "iana"
    },
    "application/vnd.japannet-registration-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-setstore-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-verification": {
        "source": "iana"
    },
    "application/vnd.japannet-verification-wakeup": {
        "source": "iana"
    },
    "application/vnd.jcp.javame.midlet-rms": {
        "source": "iana",
        "extensions": [
            "rms"
        ]
    },
    "application/vnd.jisp": {
        "source": "iana",
        "extensions": [
            "jisp"
        ]
    },
    "application/vnd.joost.joda-archive": {
        "source": "iana",
        "extensions": [
            "joda"
        ]
    },
    "application/vnd.jsk.isdn-ngn": {
        "source": "iana"
    },
    "application/vnd.kahootz": {
        "source": "iana",
        "extensions": [
            "ktz",
            "ktr"
        ]
    },
    "application/vnd.kde.karbon": {
        "source": "iana",
        "extensions": [
            "karbon"
        ]
    },
    "application/vnd.kde.kchart": {
        "source": "iana",
        "extensions": [
            "chrt"
        ]
    },
    "application/vnd.kde.kformula": {
        "source": "iana",
        "extensions": [
            "kfo"
        ]
    },
    "application/vnd.kde.kivio": {
        "source": "iana",
        "extensions": [
            "flw"
        ]
    },
    "application/vnd.kde.kontour": {
        "source": "iana",
        "extensions": [
            "kon"
        ]
    },
    "application/vnd.kde.kpresenter": {
        "source": "iana",
        "extensions": [
            "kpr",
            "kpt"
        ]
    },
    "application/vnd.kde.kspread": {
        "source": "iana",
        "extensions": [
            "ksp"
        ]
    },
    "application/vnd.kde.kword": {
        "source": "iana",
        "extensions": [
            "kwd",
            "kwt"
        ]
    },
    "application/vnd.kenameaapp": {
        "source": "iana",
        "extensions": [
            "htke"
        ]
    },
    "application/vnd.kidspiration": {
        "source": "iana",
        "extensions": [
            "kia"
        ]
    },
    "application/vnd.kinar": {
        "source": "iana",
        "extensions": [
            "kne",
            "knp"
        ]
    },
    "application/vnd.koan": {
        "source": "iana",
        "extensions": [
            "skp",
            "skd",
            "skt",
            "skm"
        ]
    },
    "application/vnd.kodak-descriptor": {
        "source": "iana",
        "extensions": [
            "sse"
        ]
    },
    "application/vnd.las": {
        "source": "iana"
    },
    "application/vnd.las.las+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.las.las+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lasxml"
        ]
    },
    "application/vnd.laszip": {
        "source": "iana"
    },
    "application/vnd.leap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.liberty-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.llamagraphics.life-balance.desktop": {
        "source": "iana",
        "extensions": [
            "lbd"
        ]
    },
    "application/vnd.llamagraphics.life-balance.exchange+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lbe"
        ]
    },
    "application/vnd.logipipe.circuit+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.loom": {
        "source": "iana"
    },
    "application/vnd.lotus-1-2-3": {
        "source": "iana",
        "extensions": [
            "123"
        ]
    },
    "application/vnd.lotus-approach": {
        "source": "iana",
        "extensions": [
            "apr"
        ]
    },
    "application/vnd.lotus-freelance": {
        "source": "iana",
        "extensions": [
            "pre"
        ]
    },
    "application/vnd.lotus-notes": {
        "source": "iana",
        "extensions": [
            "nsf"
        ]
    },
    "application/vnd.lotus-organizer": {
        "source": "iana",
        "extensions": [
            "org"
        ]
    },
    "application/vnd.lotus-screencam": {
        "source": "iana",
        "extensions": [
            "scm"
        ]
    },
    "application/vnd.lotus-wordpro": {
        "source": "iana",
        "extensions": [
            "lwp"
        ]
    },
    "application/vnd.macports.portpkg": {
        "source": "iana",
        "extensions": [
            "portpkg"
        ]
    },
    "application/vnd.mapbox-vector-tile": {
        "source": "iana",
        "extensions": [
            "mvt"
        ]
    },
    "application/vnd.marlin.drm.actiontoken+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.marlin.drm.conftoken+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.marlin.drm.license+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.marlin.drm.mdcf": {
        "source": "iana"
    },
    "application/vnd.mason+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.maxar.archive.3tz+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.maxmind.maxmind-db": {
        "source": "iana"
    },
    "application/vnd.mcd": {
        "source": "iana",
        "extensions": [
            "mcd"
        ]
    },
    "application/vnd.medcalcdata": {
        "source": "iana",
        "extensions": [
            "mc1"
        ]
    },
    "application/vnd.mediastation.cdkey": {
        "source": "iana",
        "extensions": [
            "cdkey"
        ]
    },
    "application/vnd.meridian-slingshot": {
        "source": "iana"
    },
    "application/vnd.mfer": {
        "source": "iana",
        "extensions": [
            "mwf"
        ]
    },
    "application/vnd.mfmp": {
        "source": "iana",
        "extensions": [
            "mfm"
        ]
    },
    "application/vnd.micro+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.micrografx.flo": {
        "source": "iana",
        "extensions": [
            "flo"
        ]
    },
    "application/vnd.micrografx.igx": {
        "source": "iana",
        "extensions": [
            "igx"
        ]
    },
    "application/vnd.microsoft.portable-executable": {
        "source": "iana"
    },
    "application/vnd.microsoft.windows.thumbnail-cache": {
        "source": "iana"
    },
    "application/vnd.miele+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.mif": {
        "source": "iana",
        "extensions": [
            "mif"
        ]
    },
    "application/vnd.minisoft-hp3000-save": {
        "source": "iana"
    },
    "application/vnd.mitsubishi.misty-guard.trustweb": {
        "source": "iana"
    },
    "application/vnd.mobius.daf": {
        "source": "iana",
        "extensions": [
            "daf"
        ]
    },
    "application/vnd.mobius.dis": {
        "source": "iana",
        "extensions": [
            "dis"
        ]
    },
    "application/vnd.mobius.mbk": {
        "source": "iana",
        "extensions": [
            "mbk"
        ]
    },
    "application/vnd.mobius.mqy": {
        "source": "iana",
        "extensions": [
            "mqy"
        ]
    },
    "application/vnd.mobius.msl": {
        "source": "iana",
        "extensions": [
            "msl"
        ]
    },
    "application/vnd.mobius.plc": {
        "source": "iana",
        "extensions": [
            "plc"
        ]
    },
    "application/vnd.mobius.txf": {
        "source": "iana",
        "extensions": [
            "txf"
        ]
    },
    "application/vnd.mophun.application": {
        "source": "iana",
        "extensions": [
            "mpn"
        ]
    },
    "application/vnd.mophun.certificate": {
        "source": "iana",
        "extensions": [
            "mpc"
        ]
    },
    "application/vnd.motorola.flexsuite": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.adsi": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.fis": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.gotap": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.kmr": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.ttc": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.wem": {
        "source": "iana"
    },
    "application/vnd.motorola.iprm": {
        "source": "iana"
    },
    "application/vnd.mozilla.xul+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xul"
        ]
    },
    "application/vnd.ms-3mfdocument": {
        "source": "iana"
    },
    "application/vnd.ms-artgalry": {
        "source": "iana",
        "extensions": [
            "cil"
        ]
    },
    "application/vnd.ms-asf": {
        "source": "iana"
    },
    "application/vnd.ms-cab-compressed": {
        "source": "iana",
        "extensions": [
            "cab"
        ]
    },
    "application/vnd.ms-color.iccprofile": {
        "source": "apache"
    },
    "application/vnd.ms-excel": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "xls",
            "xlm",
            "xla",
            "xlc",
            "xlt",
            "xlw"
        ]
    },
    "application/vnd.ms-excel.addin.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xlam"
        ]
    },
    "application/vnd.ms-excel.sheet.binary.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xlsb"
        ]
    },
    "application/vnd.ms-excel.sheet.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xlsm"
        ]
    },
    "application/vnd.ms-excel.template.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xltm"
        ]
    },
    "application/vnd.ms-fontobject": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "eot"
        ]
    },
    "application/vnd.ms-htmlhelp": {
        "source": "iana",
        "extensions": [
            "chm"
        ]
    },
    "application/vnd.ms-ims": {
        "source": "iana",
        "extensions": [
            "ims"
        ]
    },
    "application/vnd.ms-lrm": {
        "source": "iana",
        "extensions": [
            "lrm"
        ]
    },
    "application/vnd.ms-office.activex+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-officetheme": {
        "source": "iana",
        "extensions": [
            "thmx"
        ]
    },
    "application/vnd.ms-opentype": {
        "source": "apache",
        "compressible": true
    },
    "application/vnd.ms-outlook": {
        "compressible": false,
        "extensions": [
            "msg"
        ]
    },
    "application/vnd.ms-package.obfuscated-opentype": {
        "source": "apache"
    },
    "application/vnd.ms-pki.seccat": {
        "source": "apache",
        "extensions": [
            "cat"
        ]
    },
    "application/vnd.ms-pki.stl": {
        "source": "apache",
        "extensions": [
            "stl"
        ]
    },
    "application/vnd.ms-playready.initiator+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-powerpoint": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ppt",
            "pps",
            "pot"
        ]
    },
    "application/vnd.ms-powerpoint.addin.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "ppam"
        ]
    },
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "pptm"
        ]
    },
    "application/vnd.ms-powerpoint.slide.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "sldm"
        ]
    },
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "ppsm"
        ]
    },
    "application/vnd.ms-powerpoint.template.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "potm"
        ]
    },
    "application/vnd.ms-printdevicecapabilities+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-printing.printticket+xml": {
        "source": "apache",
        "compressible": true
    },
    "application/vnd.ms-printschematicket+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-project": {
        "source": "iana",
        "extensions": [
            "mpp",
            "mpt"
        ]
    },
    "application/vnd.ms-tnef": {
        "source": "iana"
    },
    "application/vnd.ms-windows.devicepairing": {
        "source": "iana"
    },
    "application/vnd.ms-windows.nwprinting.oob": {
        "source": "iana"
    },
    "application/vnd.ms-windows.printerpairing": {
        "source": "iana"
    },
    "application/vnd.ms-windows.wsd.oob": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.lic-chlg-req": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.lic-resp": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.meter-chlg-req": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.meter-resp": {
        "source": "iana"
    },
    "application/vnd.ms-word.document.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "docm"
        ]
    },
    "application/vnd.ms-word.template.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "dotm"
        ]
    },
    "application/vnd.ms-works": {
        "source": "iana",
        "extensions": [
            "wps",
            "wks",
            "wcm",
            "wdb"
        ]
    },
    "application/vnd.ms-wpl": {
        "source": "iana",
        "extensions": [
            "wpl"
        ]
    },
    "application/vnd.ms-xpsdocument": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "xps"
        ]
    },
    "application/vnd.msa-disk-image": {
        "source": "iana"
    },
    "application/vnd.mseq": {
        "source": "iana",
        "extensions": [
            "mseq"
        ]
    },
    "application/vnd.msign": {
        "source": "iana"
    },
    "application/vnd.multiad.creator": {
        "source": "iana"
    },
    "application/vnd.multiad.creator.cif": {
        "source": "iana"
    },
    "application/vnd.music-niff": {
        "source": "iana"
    },
    "application/vnd.musician": {
        "source": "iana",
        "extensions": [
            "mus"
        ]
    },
    "application/vnd.muvee.style": {
        "source": "iana",
        "extensions": [
            "msty"
        ]
    },
    "application/vnd.mynfc": {
        "source": "iana",
        "extensions": [
            "taglet"
        ]
    },
    "application/vnd.nacamar.ybrid+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ncd.control": {
        "source": "iana"
    },
    "application/vnd.ncd.reference": {
        "source": "iana"
    },
    "application/vnd.nearst.inv+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nebumind.line": {
        "source": "iana"
    },
    "application/vnd.nervana": {
        "source": "iana"
    },
    "application/vnd.netfpx": {
        "source": "iana"
    },
    "application/vnd.neurolanguage.nlu": {
        "source": "iana",
        "extensions": [
            "nlu"
        ]
    },
    "application/vnd.nimn": {
        "source": "iana"
    },
    "application/vnd.nintendo.nitro.rom": {
        "source": "iana"
    },
    "application/vnd.nintendo.snes.rom": {
        "source": "iana"
    },
    "application/vnd.nitf": {
        "source": "iana",
        "extensions": [
            "ntf",
            "nitf"
        ]
    },
    "application/vnd.noblenet-directory": {
        "source": "iana",
        "extensions": [
            "nnd"
        ]
    },
    "application/vnd.noblenet-sealer": {
        "source": "iana",
        "extensions": [
            "nns"
        ]
    },
    "application/vnd.noblenet-web": {
        "source": "iana",
        "extensions": [
            "nnw"
        ]
    },
    "application/vnd.nokia.catalogs": {
        "source": "iana"
    },
    "application/vnd.nokia.conml+wbxml": {
        "source": "iana"
    },
    "application/vnd.nokia.conml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.iptv.config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.isds-radio-presets": {
        "source": "iana"
    },
    "application/vnd.nokia.landmark+wbxml": {
        "source": "iana"
    },
    "application/vnd.nokia.landmark+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.landmarkcollection+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.n-gage.ac+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ac"
        ]
    },
    "application/vnd.nokia.n-gage.data": {
        "source": "iana",
        "extensions": [
            "ngdat"
        ]
    },
    "application/vnd.nokia.n-gage.symbian.install": {
        "source": "iana",
        "extensions": [
            "n-gage"
        ]
    },
    "application/vnd.nokia.ncd": {
        "source": "iana"
    },
    "application/vnd.nokia.pcd+wbxml": {
        "source": "iana"
    },
    "application/vnd.nokia.pcd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.radio-preset": {
        "source": "iana",
        "extensions": [
            "rpst"
        ]
    },
    "application/vnd.nokia.radio-presets": {
        "source": "iana",
        "extensions": [
            "rpss"
        ]
    },
    "application/vnd.novadigm.edm": {
        "source": "iana",
        "extensions": [
            "edm"
        ]
    },
    "application/vnd.novadigm.edx": {
        "source": "iana",
        "extensions": [
            "edx"
        ]
    },
    "application/vnd.novadigm.ext": {
        "source": "iana",
        "extensions": [
            "ext"
        ]
    },
    "application/vnd.ntt-local.content-share": {
        "source": "iana"
    },
    "application/vnd.ntt-local.file-transfer": {
        "source": "iana"
    },
    "application/vnd.ntt-local.ogw_remote-access": {
        "source": "iana"
    },
    "application/vnd.ntt-local.sip-ta_remote": {
        "source": "iana"
    },
    "application/vnd.ntt-local.sip-ta_tcp_stream": {
        "source": "iana"
    },
    "application/vnd.oasis.opendocument.chart": {
        "source": "iana",
        "extensions": [
            "odc"
        ]
    },
    "application/vnd.oasis.opendocument.chart-template": {
        "source": "iana",
        "extensions": [
            "otc"
        ]
    },
    "application/vnd.oasis.opendocument.database": {
        "source": "iana",
        "extensions": [
            "odb"
        ]
    },
    "application/vnd.oasis.opendocument.formula": {
        "source": "iana",
        "extensions": [
            "odf"
        ]
    },
    "application/vnd.oasis.opendocument.formula-template": {
        "source": "iana",
        "extensions": [
            "odft"
        ]
    },
    "application/vnd.oasis.opendocument.graphics": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "odg"
        ]
    },
    "application/vnd.oasis.opendocument.graphics-template": {
        "source": "iana",
        "extensions": [
            "otg"
        ]
    },
    "application/vnd.oasis.opendocument.image": {
        "source": "iana",
        "extensions": [
            "odi"
        ]
    },
    "application/vnd.oasis.opendocument.image-template": {
        "source": "iana",
        "extensions": [
            "oti"
        ]
    },
    "application/vnd.oasis.opendocument.presentation": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "odp"
        ]
    },
    "application/vnd.oasis.opendocument.presentation-template": {
        "source": "iana",
        "extensions": [
            "otp"
        ]
    },
    "application/vnd.oasis.opendocument.spreadsheet": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ods"
        ]
    },
    "application/vnd.oasis.opendocument.spreadsheet-template": {
        "source": "iana",
        "extensions": [
            "ots"
        ]
    },
    "application/vnd.oasis.opendocument.text": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "odt"
        ]
    },
    "application/vnd.oasis.opendocument.text-master": {
        "source": "iana",
        "extensions": [
            "odm"
        ]
    },
    "application/vnd.oasis.opendocument.text-template": {
        "source": "iana",
        "extensions": [
            "ott"
        ]
    },
    "application/vnd.oasis.opendocument.text-web": {
        "source": "iana",
        "extensions": [
            "oth"
        ]
    },
    "application/vnd.obn": {
        "source": "iana"
    },
    "application/vnd.ocf+cbor": {
        "source": "iana"
    },
    "application/vnd.oci.image.manifest.v1+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oftn.l10n+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.contentaccessdownload+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.contentaccessstreaming+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.cspg-hexbinary": {
        "source": "iana"
    },
    "application/vnd.oipf.dae.svg+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.dae.xhtml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.mippvcontrolmessage+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.pae.gem": {
        "source": "iana"
    },
    "application/vnd.oipf.spdiscovery+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.spdlist+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.ueprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.userprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.olpc-sugar": {
        "source": "iana",
        "extensions": [
            "xo"
        ]
    },
    "application/vnd.oma-scws-config": {
        "source": "iana"
    },
    "application/vnd.oma-scws-http-request": {
        "source": "iana"
    },
    "application/vnd.oma-scws-http-response": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.associated-procedure-parameter+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.drm-trigger+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.imd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.ltkm": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.notification+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.provisioningtrigger": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.sgboot": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.sgdd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.sgdu": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.simple-symbol-container": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.smartcard-trigger+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.sprov+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.stkm": {
        "source": "iana"
    },
    "application/vnd.oma.cab-address-book+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-feature-handler+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-pcc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-subs-invite+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-user-prefs+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.dcd": {
        "source": "iana"
    },
    "application/vnd.oma.dcdc": {
        "source": "iana"
    },
    "application/vnd.oma.dd2+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dd2"
        ]
    },
    "application/vnd.oma.drm.risd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.group-usage-list+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.lwm2m+cbor": {
        "source": "iana"
    },
    "application/vnd.oma.lwm2m+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.lwm2m+tlv": {
        "source": "iana"
    },
    "application/vnd.oma.pal+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.detailed-progress-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.final-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.groups+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.invocation-descriptor+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.optimized-progress-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.push": {
        "source": "iana"
    },
    "application/vnd.oma.scidm.messages+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.xcap-directory+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.omads-email+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.omads-file+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.omads-folder+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.omaloc-supl-init": {
        "source": "iana"
    },
    "application/vnd.onepager": {
        "source": "iana"
    },
    "application/vnd.onepagertamp": {
        "source": "iana"
    },
    "application/vnd.onepagertamx": {
        "source": "iana"
    },
    "application/vnd.onepagertat": {
        "source": "iana"
    },
    "application/vnd.onepagertatp": {
        "source": "iana"
    },
    "application/vnd.onepagertatx": {
        "source": "iana"
    },
    "application/vnd.openblox.game+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "obgx"
        ]
    },
    "application/vnd.openblox.game-binary": {
        "source": "iana"
    },
    "application/vnd.openeye.oeb": {
        "source": "iana"
    },
    "application/vnd.openofficeorg.extension": {
        "source": "apache",
        "extensions": [
            "oxt"
        ]
    },
    "application/vnd.openstreetmap.data+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "osm"
        ]
    },
    "application/vnd.opentimestamps.ots": {
        "source": "iana"
    },
    "application/vnd.openxmlformats-officedocument.custom-properties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.customxmlproperties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawing+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.chart+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramdata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.extended-properties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.commentauthors+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.comments+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.notesmaster+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.notesslide+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "pptx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presprops+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slide": {
        "source": "iana",
        "extensions": [
            "sldx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slidelayout+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slidemaster+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow": {
        "source": "iana",
        "extensions": [
            "ppsx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.tablestyles+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.tags+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.template": {
        "source": "iana",
        "extensions": [
            "potx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.viewprops+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "xlsx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template": {
        "source": "iana",
        "extensions": [
            "xltx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.theme+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.themeoverride+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.vmldrawing": {
        "source": "iana"
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "docx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template": {
        "source": "iana",
        "extensions": [
            "dotx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-package.core-properties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-package.relationships+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oracle.resource+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.orange.indata": {
        "source": "iana"
    },
    "application/vnd.osa.netdeploy": {
        "source": "iana"
    },
    "application/vnd.osgeo.mapguide.package": {
        "source": "iana",
        "extensions": [
            "mgp"
        ]
    },
    "application/vnd.osgi.bundle": {
        "source": "iana"
    },
    "application/vnd.osgi.dp": {
        "source": "iana",
        "extensions": [
            "dp"
        ]
    },
    "application/vnd.osgi.subsystem": {
        "source": "iana",
        "extensions": [
            "esa"
        ]
    },
    "application/vnd.otps.ct-kip+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oxli.countgraph": {
        "source": "iana"
    },
    "application/vnd.pagerduty+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.palm": {
        "source": "iana",
        "extensions": [
            "pdb",
            "pqa",
            "oprc"
        ]
    },
    "application/vnd.panoply": {
        "source": "iana"
    },
    "application/vnd.paos.xml": {
        "source": "iana"
    },
    "application/vnd.patentdive": {
        "source": "iana"
    },
    "application/vnd.patientecommsdoc": {
        "source": "iana"
    },
    "application/vnd.pawaafile": {
        "source": "iana",
        "extensions": [
            "paw"
        ]
    },
    "application/vnd.pcos": {
        "source": "iana"
    },
    "application/vnd.pg.format": {
        "source": "iana",
        "extensions": [
            "str"
        ]
    },
    "application/vnd.pg.osasli": {
        "source": "iana",
        "extensions": [
            "ei6"
        ]
    },
    "application/vnd.piaccess.application-licence": {
        "source": "iana"
    },
    "application/vnd.picsel": {
        "source": "iana",
        "extensions": [
            "efif"
        ]
    },
    "application/vnd.pmi.widget": {
        "source": "iana",
        "extensions": [
            "wg"
        ]
    },
    "application/vnd.poc.group-advertisement+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.pocketlearn": {
        "source": "iana",
        "extensions": [
            "plf"
        ]
    },
    "application/vnd.powerbuilder6": {
        "source": "iana",
        "extensions": [
            "pbd"
        ]
    },
    "application/vnd.powerbuilder6-s": {
        "source": "iana"
    },
    "application/vnd.powerbuilder7": {
        "source": "iana"
    },
    "application/vnd.powerbuilder7-s": {
        "source": "iana"
    },
    "application/vnd.powerbuilder75": {
        "source": "iana"
    },
    "application/vnd.powerbuilder75-s": {
        "source": "iana"
    },
    "application/vnd.preminet": {
        "source": "iana"
    },
    "application/vnd.previewsystems.box": {
        "source": "iana",
        "extensions": [
            "box"
        ]
    },
    "application/vnd.proteus.magazine": {
        "source": "iana",
        "extensions": [
            "mgz"
        ]
    },
    "application/vnd.psfs": {
        "source": "iana"
    },
    "application/vnd.publishare-delta-tree": {
        "source": "iana",
        "extensions": [
            "qps"
        ]
    },
    "application/vnd.pvi.ptid1": {
        "source": "iana",
        "extensions": [
            "ptid"
        ]
    },
    "application/vnd.pwg-multiplexed": {
        "source": "iana"
    },
    "application/vnd.pwg-xhtml-print+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.qualcomm.brew-app-res": {
        "source": "iana"
    },
    "application/vnd.quarantainenet": {
        "source": "iana"
    },
    "application/vnd.quark.quarkxpress": {
        "source": "iana",
        "extensions": [
            "qxd",
            "qxt",
            "qwd",
            "qwt",
            "qxl",
            "qxb"
        ]
    },
    "application/vnd.quobject-quoxdocument": {
        "source": "iana"
    },
    "application/vnd.radisys.moml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-conf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-conn+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-dialog+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-stream+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-conf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-base+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-fax-detect+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-fax-sendrecv+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-group+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-speech+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-transform+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.rainstor.data": {
        "source": "iana"
    },
    "application/vnd.rapid": {
        "source": "iana"
    },
    "application/vnd.rar": {
        "source": "iana",
        "extensions": [
            "rar"
        ]
    },
    "application/vnd.realvnc.bed": {
        "source": "iana",
        "extensions": [
            "bed"
        ]
    },
    "application/vnd.recordare.musicxml": {
        "source": "iana",
        "extensions": [
            "mxl"
        ]
    },
    "application/vnd.recordare.musicxml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "musicxml"
        ]
    },
    "application/vnd.renlearn.rlprint": {
        "source": "iana"
    },
    "application/vnd.resilient.logic": {
        "source": "iana"
    },
    "application/vnd.restful+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.rig.cryptonote": {
        "source": "iana",
        "extensions": [
            "cryptonote"
        ]
    },
    "application/vnd.rim.cod": {
        "source": "apache",
        "extensions": [
            "cod"
        ]
    },
    "application/vnd.rn-realmedia": {
        "source": "apache",
        "extensions": [
            "rm"
        ]
    },
    "application/vnd.rn-realmedia-vbr": {
        "source": "apache",
        "extensions": [
            "rmvb"
        ]
    },
    "application/vnd.route66.link66+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "link66"
        ]
    },
    "application/vnd.rs-274x": {
        "source": "iana"
    },
    "application/vnd.ruckus.download": {
        "source": "iana"
    },
    "application/vnd.s3sms": {
        "source": "iana"
    },
    "application/vnd.sailingtracker.track": {
        "source": "iana",
        "extensions": [
            "st"
        ]
    },
    "application/vnd.sar": {
        "source": "iana"
    },
    "application/vnd.sbm.cid": {
        "source": "iana"
    },
    "application/vnd.sbm.mid2": {
        "source": "iana"
    },
    "application/vnd.scribus": {
        "source": "iana"
    },
    "application/vnd.sealed.3df": {
        "source": "iana"
    },
    "application/vnd.sealed.csf": {
        "source": "iana"
    },
    "application/vnd.sealed.doc": {
        "source": "iana"
    },
    "application/vnd.sealed.eml": {
        "source": "iana"
    },
    "application/vnd.sealed.mht": {
        "source": "iana"
    },
    "application/vnd.sealed.net": {
        "source": "iana"
    },
    "application/vnd.sealed.ppt": {
        "source": "iana"
    },
    "application/vnd.sealed.tiff": {
        "source": "iana"
    },
    "application/vnd.sealed.xls": {
        "source": "iana"
    },
    "application/vnd.sealedmedia.softseal.html": {
        "source": "iana"
    },
    "application/vnd.sealedmedia.softseal.pdf": {
        "source": "iana"
    },
    "application/vnd.seemail": {
        "source": "iana",
        "extensions": [
            "see"
        ]
    },
    "application/vnd.seis+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.sema": {
        "source": "iana",
        "extensions": [
            "sema"
        ]
    },
    "application/vnd.semd": {
        "source": "iana",
        "extensions": [
            "semd"
        ]
    },
    "application/vnd.semf": {
        "source": "iana",
        "extensions": [
            "semf"
        ]
    },
    "application/vnd.shade-save-file": {
        "source": "iana"
    },
    "application/vnd.shana.informed.formdata": {
        "source": "iana",
        "extensions": [
            "ifm"
        ]
    },
    "application/vnd.shana.informed.formtemplate": {
        "source": "iana",
        "extensions": [
            "itp"
        ]
    },
    "application/vnd.shana.informed.interchange": {
        "source": "iana",
        "extensions": [
            "iif"
        ]
    },
    "application/vnd.shana.informed.package": {
        "source": "iana",
        "extensions": [
            "ipk"
        ]
    },
    "application/vnd.shootproof+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.shopkick+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.shp": {
        "source": "iana"
    },
    "application/vnd.shx": {
        "source": "iana"
    },
    "application/vnd.sigrok.session": {
        "source": "iana"
    },
    "application/vnd.simtech-mindmapper": {
        "source": "iana",
        "extensions": [
            "twd",
            "twds"
        ]
    },
    "application/vnd.siren+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.smaf": {
        "source": "iana",
        "extensions": [
            "mmf"
        ]
    },
    "application/vnd.smart.notebook": {
        "source": "iana"
    },
    "application/vnd.smart.teacher": {
        "source": "iana",
        "extensions": [
            "teacher"
        ]
    },
    "application/vnd.snesdev-page-table": {
        "source": "iana"
    },
    "application/vnd.software602.filler.form+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "fo"
        ]
    },
    "application/vnd.software602.filler.form-xml-zip": {
        "source": "iana"
    },
    "application/vnd.solent.sdkm+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sdkm",
            "sdkd"
        ]
    },
    "application/vnd.spotfire.dxp": {
        "source": "iana",
        "extensions": [
            "dxp"
        ]
    },
    "application/vnd.spotfire.sfs": {
        "source": "iana",
        "extensions": [
            "sfs"
        ]
    },
    "application/vnd.sqlite3": {
        "source": "iana"
    },
    "application/vnd.sss-cod": {
        "source": "iana"
    },
    "application/vnd.sss-dtf": {
        "source": "iana"
    },
    "application/vnd.sss-ntf": {
        "source": "iana"
    },
    "application/vnd.stardivision.calc": {
        "source": "apache",
        "extensions": [
            "sdc"
        ]
    },
    "application/vnd.stardivision.draw": {
        "source": "apache",
        "extensions": [
            "sda"
        ]
    },
    "application/vnd.stardivision.impress": {
        "source": "apache",
        "extensions": [
            "sdd"
        ]
    },
    "application/vnd.stardivision.math": {
        "source": "apache",
        "extensions": [
            "smf"
        ]
    },
    "application/vnd.stardivision.writer": {
        "source": "apache",
        "extensions": [
            "sdw",
            "vor"
        ]
    },
    "application/vnd.stardivision.writer-global": {
        "source": "apache",
        "extensions": [
            "sgl"
        ]
    },
    "application/vnd.stepmania.package": {
        "source": "iana",
        "extensions": [
            "smzip"
        ]
    },
    "application/vnd.stepmania.stepchart": {
        "source": "iana",
        "extensions": [
            "sm"
        ]
    },
    "application/vnd.street-stream": {
        "source": "iana"
    },
    "application/vnd.sun.wadl+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wadl"
        ]
    },
    "application/vnd.sun.xml.calc": {
        "source": "apache",
        "extensions": [
            "sxc"
        ]
    },
    "application/vnd.sun.xml.calc.template": {
        "source": "apache",
        "extensions": [
            "stc"
        ]
    },
    "application/vnd.sun.xml.draw": {
        "source": "apache",
        "extensions": [
            "sxd"
        ]
    },
    "application/vnd.sun.xml.draw.template": {
        "source": "apache",
        "extensions": [
            "std"
        ]
    },
    "application/vnd.sun.xml.impress": {
        "source": "apache",
        "extensions": [
            "sxi"
        ]
    },
    "application/vnd.sun.xml.impress.template": {
        "source": "apache",
        "extensions": [
            "sti"
        ]
    },
    "application/vnd.sun.xml.math": {
        "source": "apache",
        "extensions": [
            "sxm"
        ]
    },
    "application/vnd.sun.xml.writer": {
        "source": "apache",
        "extensions": [
            "sxw"
        ]
    },
    "application/vnd.sun.xml.writer.global": {
        "source": "apache",
        "extensions": [
            "sxg"
        ]
    },
    "application/vnd.sun.xml.writer.template": {
        "source": "apache",
        "extensions": [
            "stw"
        ]
    },
    "application/vnd.sus-calendar": {
        "source": "iana",
        "extensions": [
            "sus",
            "susp"
        ]
    },
    "application/vnd.svd": {
        "source": "iana",
        "extensions": [
            "svd"
        ]
    },
    "application/vnd.swiftview-ics": {
        "source": "iana"
    },
    "application/vnd.sycle+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.syft+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.symbian.install": {
        "source": "apache",
        "extensions": [
            "sis",
            "sisx"
        ]
    },
    "application/vnd.syncml+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "xsm"
        ]
    },
    "application/vnd.syncml.dm+wbxml": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "bdm"
        ]
    },
    "application/vnd.syncml.dm+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "xdm"
        ]
    },
    "application/vnd.syncml.dm.notification": {
        "source": "iana"
    },
    "application/vnd.syncml.dmddf+wbxml": {
        "source": "iana"
    },
    "application/vnd.syncml.dmddf+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "ddf"
        ]
    },
    "application/vnd.syncml.dmtnds+wbxml": {
        "source": "iana"
    },
    "application/vnd.syncml.dmtnds+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.syncml.ds.notification": {
        "source": "iana"
    },
    "application/vnd.tableschema+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.tao.intent-module-archive": {
        "source": "iana",
        "extensions": [
            "tao"
        ]
    },
    "application/vnd.tcpdump.pcap": {
        "source": "iana",
        "extensions": [
            "pcap",
            "cap",
            "dmp"
        ]
    },
    "application/vnd.think-cell.ppttc+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.tmd.mediaflex.api+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.tml": {
        "source": "iana"
    },
    "application/vnd.tmobile-livetv": {
        "source": "iana",
        "extensions": [
            "tmo"
        ]
    },
    "application/vnd.tri.onesource": {
        "source": "iana"
    },
    "application/vnd.trid.tpt": {
        "source": "iana",
        "extensions": [
            "tpt"
        ]
    },
    "application/vnd.triscape.mxs": {
        "source": "iana",
        "extensions": [
            "mxs"
        ]
    },
    "application/vnd.trueapp": {
        "source": "iana",
        "extensions": [
            "tra"
        ]
    },
    "application/vnd.truedoc": {
        "source": "iana"
    },
    "application/vnd.ubisoft.webplayer": {
        "source": "iana"
    },
    "application/vnd.ufdl": {
        "source": "iana",
        "extensions": [
            "ufd",
            "ufdl"
        ]
    },
    "application/vnd.uiq.theme": {
        "source": "iana",
        "extensions": [
            "utz"
        ]
    },
    "application/vnd.umajin": {
        "source": "iana",
        "extensions": [
            "umj"
        ]
    },
    "application/vnd.unity": {
        "source": "iana",
        "extensions": [
            "unityweb"
        ]
    },
    "application/vnd.uoml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "uoml"
        ]
    },
    "application/vnd.uplanet.alert": {
        "source": "iana"
    },
    "application/vnd.uplanet.alert-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.bearer-choice": {
        "source": "iana"
    },
    "application/vnd.uplanet.bearer-choice-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.cacheop": {
        "source": "iana"
    },
    "application/vnd.uplanet.cacheop-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.channel": {
        "source": "iana"
    },
    "application/vnd.uplanet.channel-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.list": {
        "source": "iana"
    },
    "application/vnd.uplanet.list-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.listcmd": {
        "source": "iana"
    },
    "application/vnd.uplanet.listcmd-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.signal": {
        "source": "iana"
    },
    "application/vnd.uri-map": {
        "source": "iana"
    },
    "application/vnd.valve.source.material": {
        "source": "iana"
    },
    "application/vnd.vcx": {
        "source": "iana",
        "extensions": [
            "vcx"
        ]
    },
    "application/vnd.vd-study": {
        "source": "iana"
    },
    "application/vnd.vectorworks": {
        "source": "iana"
    },
    "application/vnd.vel+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.verimatrix.vcas": {
        "source": "iana"
    },
    "application/vnd.veritone.aion+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.veryant.thin": {
        "source": "iana"
    },
    "application/vnd.ves.encrypted": {
        "source": "iana"
    },
    "application/vnd.vidsoft.vidconference": {
        "source": "iana"
    },
    "application/vnd.visio": {
        "source": "iana",
        "extensions": [
            "vsd",
            "vst",
            "vss",
            "vsw"
        ]
    },
    "application/vnd.visionary": {
        "source": "iana",
        "extensions": [
            "vis"
        ]
    },
    "application/vnd.vividence.scriptfile": {
        "source": "iana"
    },
    "application/vnd.vsf": {
        "source": "iana",
        "extensions": [
            "vsf"
        ]
    },
    "application/vnd.wap.sic": {
        "source": "iana"
    },
    "application/vnd.wap.slc": {
        "source": "iana"
    },
    "application/vnd.wap.wbxml": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "wbxml"
        ]
    },
    "application/vnd.wap.wmlc": {
        "source": "iana",
        "extensions": [
            "wmlc"
        ]
    },
    "application/vnd.wap.wmlscriptc": {
        "source": "iana",
        "extensions": [
            "wmlsc"
        ]
    },
    "application/vnd.webturbo": {
        "source": "iana",
        "extensions": [
            "wtb"
        ]
    },
    "application/vnd.wfa.dpp": {
        "source": "iana"
    },
    "application/vnd.wfa.p2p": {
        "source": "iana"
    },
    "application/vnd.wfa.wsc": {
        "source": "iana"
    },
    "application/vnd.windows.devicepairing": {
        "source": "iana"
    },
    "application/vnd.wmc": {
        "source": "iana"
    },
    "application/vnd.wmf.bootstrap": {
        "source": "iana"
    },
    "application/vnd.wolfram.mathematica": {
        "source": "iana"
    },
    "application/vnd.wolfram.mathematica.package": {
        "source": "iana"
    },
    "application/vnd.wolfram.player": {
        "source": "iana",
        "extensions": [
            "nbp"
        ]
    },
    "application/vnd.wordperfect": {
        "source": "iana",
        "extensions": [
            "wpd"
        ]
    },
    "application/vnd.wqd": {
        "source": "iana",
        "extensions": [
            "wqd"
        ]
    },
    "application/vnd.wrq-hp3000-labelled": {
        "source": "iana"
    },
    "application/vnd.wt.stf": {
        "source": "iana",
        "extensions": [
            "stf"
        ]
    },
    "application/vnd.wv.csp+wbxml": {
        "source": "iana"
    },
    "application/vnd.wv.csp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.wv.ssp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.xacml+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.xara": {
        "source": "iana",
        "extensions": [
            "xar"
        ]
    },
    "application/vnd.xfdl": {
        "source": "iana",
        "extensions": [
            "xfdl"
        ]
    },
    "application/vnd.xfdl.webform": {
        "source": "iana"
    },
    "application/vnd.xmi+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.xmpie.cpkg": {
        "source": "iana"
    },
    "application/vnd.xmpie.dpkg": {
        "source": "iana"
    },
    "application/vnd.xmpie.plan": {
        "source": "iana"
    },
    "application/vnd.xmpie.ppkg": {
        "source": "iana"
    },
    "application/vnd.xmpie.xlim": {
        "source": "iana"
    },
    "application/vnd.yamaha.hv-dic": {
        "source": "iana",
        "extensions": [
            "hvd"
        ]
    },
    "application/vnd.yamaha.hv-script": {
        "source": "iana",
        "extensions": [
            "hvs"
        ]
    },
    "application/vnd.yamaha.hv-voice": {
        "source": "iana",
        "extensions": [
            "hvp"
        ]
    },
    "application/vnd.yamaha.openscoreformat": {
        "source": "iana",
        "extensions": [
            "osf"
        ]
    },
    "application/vnd.yamaha.openscoreformat.osfpvg+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "osfpvg"
        ]
    },
    "application/vnd.yamaha.remote-setup": {
        "source": "iana"
    },
    "application/vnd.yamaha.smaf-audio": {
        "source": "iana",
        "extensions": [
            "saf"
        ]
    },
    "application/vnd.yamaha.smaf-phrase": {
        "source": "iana",
        "extensions": [
            "spf"
        ]
    },
    "application/vnd.yamaha.through-ngn": {
        "source": "iana"
    },
    "application/vnd.yamaha.tunnel-udpencap": {
        "source": "iana"
    },
    "application/vnd.yaoweme": {
        "source": "iana"
    },
    "application/vnd.yellowriver-custom-menu": {
        "source": "iana",
        "extensions": [
            "cmp"
        ]
    },
    "application/vnd.youtube.yt": {
        "source": "iana"
    },
    "application/vnd.zul": {
        "source": "iana",
        "extensions": [
            "zir",
            "zirz"
        ]
    },
    "application/vnd.zzazz.deck+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "zaz"
        ]
    },
    "application/voicexml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "vxml"
        ]
    },
    "application/voucher-cms+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vq-rtcpxr": {
        "source": "iana"
    },
    "application/wasm": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wasm"
        ]
    },
    "application/watcherinfo+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wif"
        ]
    },
    "application/webpush-options+json": {
        "source": "iana",
        "compressible": true
    },
    "application/whoispp-query": {
        "source": "iana"
    },
    "application/whoispp-response": {
        "source": "iana"
    },
    "application/widget": {
        "source": "iana",
        "extensions": [
            "wgt"
        ]
    },
    "application/winhlp": {
        "source": "apache",
        "extensions": [
            "hlp"
        ]
    },
    "application/wita": {
        "source": "iana"
    },
    "application/wordperfect5.1": {
        "source": "iana"
    },
    "application/wsdl+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wsdl"
        ]
    },
    "application/wspolicy+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wspolicy"
        ]
    },
    "application/x-7z-compressed": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "7z"
        ]
    },
    "application/x-abiword": {
        "source": "apache",
        "extensions": [
            "abw"
        ]
    },
    "application/x-ace-compressed": {
        "source": "apache",
        "extensions": [
            "ace"
        ]
    },
    "application/x-amf": {
        "source": "apache"
    },
    "application/x-apple-diskimage": {
        "source": "apache",
        "extensions": [
            "dmg"
        ]
    },
    "application/x-arj": {
        "compressible": false,
        "extensions": [
            "arj"
        ]
    },
    "application/x-authorware-bin": {
        "source": "apache",
        "extensions": [
            "aab",
            "x32",
            "u32",
            "vox"
        ]
    },
    "application/x-authorware-map": {
        "source": "apache",
        "extensions": [
            "aam"
        ]
    },
    "application/x-authorware-seg": {
        "source": "apache",
        "extensions": [
            "aas"
        ]
    },
    "application/x-bcpio": {
        "source": "apache",
        "extensions": [
            "bcpio"
        ]
    },
    "application/x-bdoc": {
        "compressible": false,
        "extensions": [
            "bdoc"
        ]
    },
    "application/x-bittorrent": {
        "source": "apache",
        "extensions": [
            "torrent"
        ]
    },
    "application/x-blorb": {
        "source": "apache",
        "extensions": [
            "blb",
            "blorb"
        ]
    },
    "application/x-bzip": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "bz"
        ]
    },
    "application/x-bzip2": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "bz2",
            "boz"
        ]
    },
    "application/x-cbr": {
        "source": "apache",
        "extensions": [
            "cbr",
            "cba",
            "cbt",
            "cbz",
            "cb7"
        ]
    },
    "application/x-cdlink": {
        "source": "apache",
        "extensions": [
            "vcd"
        ]
    },
    "application/x-cfs-compressed": {
        "source": "apache",
        "extensions": [
            "cfs"
        ]
    },
    "application/x-chat": {
        "source": "apache",
        "extensions": [
            "chat"
        ]
    },
    "application/x-chess-pgn": {
        "source": "apache",
        "extensions": [
            "pgn"
        ]
    },
    "application/x-chrome-extension": {
        "extensions": [
            "crx"
        ]
    },
    "application/x-cocoa": {
        "source": "nginx",
        "extensions": [
            "cco"
        ]
    },
    "application/x-compress": {
        "source": "apache"
    },
    "application/x-conference": {
        "source": "apache",
        "extensions": [
            "nsc"
        ]
    },
    "application/x-cpio": {
        "source": "apache",
        "extensions": [
            "cpio"
        ]
    },
    "application/x-csh": {
        "source": "apache",
        "extensions": [
            "csh"
        ]
    },
    "application/x-deb": {
        "compressible": false
    },
    "application/x-debian-package": {
        "source": "apache",
        "extensions": [
            "deb",
            "udeb"
        ]
    },
    "application/x-dgc-compressed": {
        "source": "apache",
        "extensions": [
            "dgc"
        ]
    },
    "application/x-director": {
        "source": "apache",
        "extensions": [
            "dir",
            "dcr",
            "dxr",
            "cst",
            "cct",
            "cxt",
            "w3d",
            "fgd",
            "swa"
        ]
    },
    "application/x-doom": {
        "source": "apache",
        "extensions": [
            "wad"
        ]
    },
    "application/x-dtbncx+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "ncx"
        ]
    },
    "application/x-dtbook+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "dtb"
        ]
    },
    "application/x-dtbresource+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "res"
        ]
    },
    "application/x-dvi": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "dvi"
        ]
    },
    "application/x-envoy": {
        "source": "apache",
        "extensions": [
            "evy"
        ]
    },
    "application/x-eva": {
        "source": "apache",
        "extensions": [
            "eva"
        ]
    },
    "application/x-font-bdf": {
        "source": "apache",
        "extensions": [
            "bdf"
        ]
    },
    "application/x-font-dos": {
        "source": "apache"
    },
    "application/x-font-framemaker": {
        "source": "apache"
    },
    "application/x-font-ghostscript": {
        "source": "apache",
        "extensions": [
            "gsf"
        ]
    },
    "application/x-font-libgrx": {
        "source": "apache"
    },
    "application/x-font-linux-psf": {
        "source": "apache",
        "extensions": [
            "psf"
        ]
    },
    "application/x-font-pcf": {
        "source": "apache",
        "extensions": [
            "pcf"
        ]
    },
    "application/x-font-snf": {
        "source": "apache",
        "extensions": [
            "snf"
        ]
    },
    "application/x-font-speedo": {
        "source": "apache"
    },
    "application/x-font-sunos-news": {
        "source": "apache"
    },
    "application/x-font-type1": {
        "source": "apache",
        "extensions": [
            "pfa",
            "pfb",
            "pfm",
            "afm"
        ]
    },
    "application/x-font-vfont": {
        "source": "apache"
    },
    "application/x-freearc": {
        "source": "apache",
        "extensions": [
            "arc"
        ]
    },
    "application/x-futuresplash": {
        "source": "apache",
        "extensions": [
            "spl"
        ]
    },
    "application/x-gca-compressed": {
        "source": "apache",
        "extensions": [
            "gca"
        ]
    },
    "application/x-glulx": {
        "source": "apache",
        "extensions": [
            "ulx"
        ]
    },
    "application/x-gnumeric": {
        "source": "apache",
        "extensions": [
            "gnumeric"
        ]
    },
    "application/x-gramps-xml": {
        "source": "apache",
        "extensions": [
            "gramps"
        ]
    },
    "application/x-gtar": {
        "source": "apache",
        "extensions": [
            "gtar"
        ]
    },
    "application/x-gzip": {
        "source": "apache"
    },
    "application/x-hdf": {
        "source": "apache",
        "extensions": [
            "hdf"
        ]
    },
    "application/x-httpd-php": {
        "compressible": true,
        "extensions": [
            "php"
        ]
    },
    "application/x-install-instructions": {
        "source": "apache",
        "extensions": [
            "install"
        ]
    },
    "application/x-iso9660-image": {
        "source": "apache",
        "extensions": [
            "iso"
        ]
    },
    "application/x-iwork-keynote-sffkey": {
        "extensions": [
            "key"
        ]
    },
    "application/x-iwork-numbers-sffnumbers": {
        "extensions": [
            "numbers"
        ]
    },
    "application/x-iwork-pages-sffpages": {
        "extensions": [
            "pages"
        ]
    },
    "application/x-java-archive-diff": {
        "source": "nginx",
        "extensions": [
            "jardiff"
        ]
    },
    "application/x-java-jnlp-file": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "jnlp"
        ]
    },
    "application/x-javascript": {
        "compressible": true
    },
    "application/x-keepass2": {
        "extensions": [
            "kdbx"
        ]
    },
    "application/x-latex": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "latex"
        ]
    },
    "application/x-lua-bytecode": {
        "extensions": [
            "luac"
        ]
    },
    "application/x-lzh-compressed": {
        "source": "apache",
        "extensions": [
            "lzh",
            "lha"
        ]
    },
    "application/x-makeself": {
        "source": "nginx",
        "extensions": [
            "run"
        ]
    },
    "application/x-mie": {
        "source": "apache",
        "extensions": [
            "mie"
        ]
    },
    "application/x-mobipocket-ebook": {
        "source": "apache",
        "extensions": [
            "prc",
            "mobi"
        ]
    },
    "application/x-mpegurl": {
        "compressible": false
    },
    "application/x-ms-application": {
        "source": "apache",
        "extensions": [
            "application"
        ]
    },
    "application/x-ms-shortcut": {
        "source": "apache",
        "extensions": [
            "lnk"
        ]
    },
    "application/x-ms-wmd": {
        "source": "apache",
        "extensions": [
            "wmd"
        ]
    },
    "application/x-ms-wmz": {
        "source": "apache",
        "extensions": [
            "wmz"
        ]
    },
    "application/x-ms-xbap": {
        "source": "apache",
        "extensions": [
            "xbap"
        ]
    },
    "application/x-msaccess": {
        "source": "apache",
        "extensions": [
            "mdb"
        ]
    },
    "application/x-msbinder": {
        "source": "apache",
        "extensions": [
            "obd"
        ]
    },
    "application/x-mscardfile": {
        "source": "apache",
        "extensions": [
            "crd"
        ]
    },
    "application/x-msclip": {
        "source": "apache",
        "extensions": [
            "clp"
        ]
    },
    "application/x-msdos-program": {
        "extensions": [
            "exe"
        ]
    },
    "application/x-msdownload": {
        "source": "apache",
        "extensions": [
            "exe",
            "dll",
            "com",
            "bat",
            "msi"
        ]
    },
    "application/x-msmediaview": {
        "source": "apache",
        "extensions": [
            "mvb",
            "m13",
            "m14"
        ]
    },
    "application/x-msmetafile": {
        "source": "apache",
        "extensions": [
            "wmf",
            "wmz",
            "emf",
            "emz"
        ]
    },
    "application/x-msmoney": {
        "source": "apache",
        "extensions": [
            "mny"
        ]
    },
    "application/x-mspublisher": {
        "source": "apache",
        "extensions": [
            "pub"
        ]
    },
    "application/x-msschedule": {
        "source": "apache",
        "extensions": [
            "scd"
        ]
    },
    "application/x-msterminal": {
        "source": "apache",
        "extensions": [
            "trm"
        ]
    },
    "application/x-mswrite": {
        "source": "apache",
        "extensions": [
            "wri"
        ]
    },
    "application/x-netcdf": {
        "source": "apache",
        "extensions": [
            "nc",
            "cdf"
        ]
    },
    "application/x-ns-proxy-autoconfig": {
        "compressible": true,
        "extensions": [
            "pac"
        ]
    },
    "application/x-nzb": {
        "source": "apache",
        "extensions": [
            "nzb"
        ]
    },
    "application/x-perl": {
        "source": "nginx",
        "extensions": [
            "pl",
            "pm"
        ]
    },
    "application/x-pilot": {
        "source": "nginx",
        "extensions": [
            "prc",
            "pdb"
        ]
    },
    "application/x-pkcs12": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "p12",
            "pfx"
        ]
    },
    "application/x-pkcs7-certificates": {
        "source": "apache",
        "extensions": [
            "p7b",
            "spc"
        ]
    },
    "application/x-pkcs7-certreqresp": {
        "source": "apache",
        "extensions": [
            "p7r"
        ]
    },
    "application/x-pki-message": {
        "source": "iana"
    },
    "application/x-rar-compressed": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "rar"
        ]
    },
    "application/x-redhat-package-manager": {
        "source": "nginx",
        "extensions": [
            "rpm"
        ]
    },
    "application/x-research-info-systems": {
        "source": "apache",
        "extensions": [
            "ris"
        ]
    },
    "application/x-sea": {
        "source": "nginx",
        "extensions": [
            "sea"
        ]
    },
    "application/x-sh": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "sh"
        ]
    },
    "application/x-shar": {
        "source": "apache",
        "extensions": [
            "shar"
        ]
    },
    "application/x-shockwave-flash": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "swf"
        ]
    },
    "application/x-silverlight-app": {
        "source": "apache",
        "extensions": [
            "xap"
        ]
    },
    "application/x-sql": {
        "source": "apache",
        "extensions": [
            "sql"
        ]
    },
    "application/x-stuffit": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "sit"
        ]
    },
    "application/x-stuffitx": {
        "source": "apache",
        "extensions": [
            "sitx"
        ]
    },
    "application/x-subrip": {
        "source": "apache",
        "extensions": [
            "srt"
        ]
    },
    "application/x-sv4cpio": {
        "source": "apache",
        "extensions": [
            "sv4cpio"
        ]
    },
    "application/x-sv4crc": {
        "source": "apache",
        "extensions": [
            "sv4crc"
        ]
    },
    "application/x-t3vm-image": {
        "source": "apache",
        "extensions": [
            "t3"
        ]
    },
    "application/x-tads": {
        "source": "apache",
        "extensions": [
            "gam"
        ]
    },
    "application/x-tar": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "tar"
        ]
    },
    "application/x-tcl": {
        "source": "apache",
        "extensions": [
            "tcl",
            "tk"
        ]
    },
    "application/x-tex": {
        "source": "apache",
        "extensions": [
            "tex"
        ]
    },
    "application/x-tex-tfm": {
        "source": "apache",
        "extensions": [
            "tfm"
        ]
    },
    "application/x-texinfo": {
        "source": "apache",
        "extensions": [
            "texinfo",
            "texi"
        ]
    },
    "application/x-tgif": {
        "source": "apache",
        "extensions": [
            "obj"
        ]
    },
    "application/x-ustar": {
        "source": "apache",
        "extensions": [
            "ustar"
        ]
    },
    "application/x-virtualbox-hdd": {
        "compressible": true,
        "extensions": [
            "hdd"
        ]
    },
    "application/x-virtualbox-ova": {
        "compressible": true,
        "extensions": [
            "ova"
        ]
    },
    "application/x-virtualbox-ovf": {
        "compressible": true,
        "extensions": [
            "ovf"
        ]
    },
    "application/x-virtualbox-vbox": {
        "compressible": true,
        "extensions": [
            "vbox"
        ]
    },
    "application/x-virtualbox-vbox-extpack": {
        "compressible": false,
        "extensions": [
            "vbox-extpack"
        ]
    },
    "application/x-virtualbox-vdi": {
        "compressible": true,
        "extensions": [
            "vdi"
        ]
    },
    "application/x-virtualbox-vhd": {
        "compressible": true,
        "extensions": [
            "vhd"
        ]
    },
    "application/x-virtualbox-vmdk": {
        "compressible": true,
        "extensions": [
            "vmdk"
        ]
    },
    "application/x-wais-source": {
        "source": "apache",
        "extensions": [
            "src"
        ]
    },
    "application/x-web-app-manifest+json": {
        "compressible": true,
        "extensions": [
            "webapp"
        ]
    },
    "application/x-www-form-urlencoded": {
        "source": "iana",
        "compressible": true
    },
    "application/x-x509-ca-cert": {
        "source": "iana",
        "extensions": [
            "der",
            "crt",
            "pem"
        ]
    },
    "application/x-x509-ca-ra-cert": {
        "source": "iana"
    },
    "application/x-x509-next-ca-cert": {
        "source": "iana"
    },
    "application/x-xfig": {
        "source": "apache",
        "extensions": [
            "fig"
        ]
    },
    "application/x-xliff+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xlf"
        ]
    },
    "application/x-xpinstall": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "xpi"
        ]
    },
    "application/x-xz": {
        "source": "apache",
        "extensions": [
            "xz"
        ]
    },
    "application/x-zmachine": {
        "source": "apache",
        "extensions": [
            "z1",
            "z2",
            "z3",
            "z4",
            "z5",
            "z6",
            "z7",
            "z8"
        ]
    },
    "application/x400-bp": {
        "source": "iana"
    },
    "application/xacml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xaml+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xaml"
        ]
    },
    "application/xcap-att+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xav"
        ]
    },
    "application/xcap-caps+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xca"
        ]
    },
    "application/xcap-diff+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xdf"
        ]
    },
    "application/xcap-el+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xel"
        ]
    },
    "application/xcap-error+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xcap-ns+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xns"
        ]
    },
    "application/xcon-conference-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xcon-conference-info-diff+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xenc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xenc"
        ]
    },
    "application/xhtml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xhtml",
            "xht"
        ]
    },
    "application/xhtml-voice+xml": {
        "source": "apache",
        "compressible": true
    },
    "application/xliff+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xlf"
        ]
    },
    "application/xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xml",
            "xsl",
            "xsd",
            "rng"
        ]
    },
    "application/xml-dtd": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dtd"
        ]
    },
    "application/xml-external-parsed-entity": {
        "source": "iana"
    },
    "application/xml-patch+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xmpp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xop+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xop"
        ]
    },
    "application/xproc+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xpl"
        ]
    },
    "application/xslt+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xsl",
            "xslt"
        ]
    },
    "application/xspf+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xspf"
        ]
    },
    "application/xv+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mxml",
            "xhvml",
            "xvml",
            "xvm"
        ]
    },
    "application/yang": {
        "source": "iana",
        "extensions": [
            "yang"
        ]
    },
    "application/yang-data+json": {
        "source": "iana",
        "compressible": true
    },
    "application/yang-data+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/yang-patch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/yang-patch+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/yin+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "yin"
        ]
    },
    "application/zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "zip"
        ]
    },
    "application/zlib": {
        "source": "iana"
    },
    "application/zstd": {
        "source": "iana"
    },
    "audio/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "audio/32kadpcm": {
        "source": "iana"
    },
    "audio/3gpp": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "3gpp"
        ]
    },
    "audio/3gpp2": {
        "source": "iana"
    },
    "audio/aac": {
        "source": "iana"
    },
    "audio/ac3": {
        "source": "iana"
    },
    "audio/adpcm": {
        "source": "apache",
        "extensions": [
            "adp"
        ]
    },
    "audio/amr": {
        "source": "iana",
        "extensions": [
            "amr"
        ]
    },
    "audio/amr-wb": {
        "source": "iana"
    },
    "audio/amr-wb+": {
        "source": "iana"
    },
    "audio/aptx": {
        "source": "iana"
    },
    "audio/asc": {
        "source": "iana"
    },
    "audio/atrac-advanced-lossless": {
        "source": "iana"
    },
    "audio/atrac-x": {
        "source": "iana"
    },
    "audio/atrac3": {
        "source": "iana"
    },
    "audio/basic": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "au",
            "snd"
        ]
    },
    "audio/bv16": {
        "source": "iana"
    },
    "audio/bv32": {
        "source": "iana"
    },
    "audio/clearmode": {
        "source": "iana"
    },
    "audio/cn": {
        "source": "iana"
    },
    "audio/dat12": {
        "source": "iana"
    },
    "audio/dls": {
        "source": "iana"
    },
    "audio/dsr-es201108": {
        "source": "iana"
    },
    "audio/dsr-es202050": {
        "source": "iana"
    },
    "audio/dsr-es202211": {
        "source": "iana"
    },
    "audio/dsr-es202212": {
        "source": "iana"
    },
    "audio/dv": {
        "source": "iana"
    },
    "audio/dvi4": {
        "source": "iana"
    },
    "audio/eac3": {
        "source": "iana"
    },
    "audio/encaprtp": {
        "source": "iana"
    },
    "audio/evrc": {
        "source": "iana"
    },
    "audio/evrc-qcp": {
        "source": "iana"
    },
    "audio/evrc0": {
        "source": "iana"
    },
    "audio/evrc1": {
        "source": "iana"
    },
    "audio/evrcb": {
        "source": "iana"
    },
    "audio/evrcb0": {
        "source": "iana"
    },
    "audio/evrcb1": {
        "source": "iana"
    },
    "audio/evrcnw": {
        "source": "iana"
    },
    "audio/evrcnw0": {
        "source": "iana"
    },
    "audio/evrcnw1": {
        "source": "iana"
    },
    "audio/evrcwb": {
        "source": "iana"
    },
    "audio/evrcwb0": {
        "source": "iana"
    },
    "audio/evrcwb1": {
        "source": "iana"
    },
    "audio/evs": {
        "source": "iana"
    },
    "audio/flexfec": {
        "source": "iana"
    },
    "audio/fwdred": {
        "source": "iana"
    },
    "audio/g711-0": {
        "source": "iana"
    },
    "audio/g719": {
        "source": "iana"
    },
    "audio/g722": {
        "source": "iana"
    },
    "audio/g7221": {
        "source": "iana"
    },
    "audio/g723": {
        "source": "iana"
    },
    "audio/g726-16": {
        "source": "iana"
    },
    "audio/g726-24": {
        "source": "iana"
    },
    "audio/g726-32": {
        "source": "iana"
    },
    "audio/g726-40": {
        "source": "iana"
    },
    "audio/g728": {
        "source": "iana"
    },
    "audio/g729": {
        "source": "iana"
    },
    "audio/g7291": {
        "source": "iana"
    },
    "audio/g729d": {
        "source": "iana"
    },
    "audio/g729e": {
        "source": "iana"
    },
    "audio/gsm": {
        "source": "iana"
    },
    "audio/gsm-efr": {
        "source": "iana"
    },
    "audio/gsm-hr-08": {
        "source": "iana"
    },
    "audio/ilbc": {
        "source": "iana"
    },
    "audio/ip-mr_v2.5": {
        "source": "iana"
    },
    "audio/isac": {
        "source": "apache"
    },
    "audio/l16": {
        "source": "iana"
    },
    "audio/l20": {
        "source": "iana"
    },
    "audio/l24": {
        "source": "iana",
        "compressible": false
    },
    "audio/l8": {
        "source": "iana"
    },
    "audio/lpc": {
        "source": "iana"
    },
    "audio/melp": {
        "source": "iana"
    },
    "audio/melp1200": {
        "source": "iana"
    },
    "audio/melp2400": {
        "source": "iana"
    },
    "audio/melp600": {
        "source": "iana"
    },
    "audio/mhas": {
        "source": "iana"
    },
    "audio/midi": {
        "source": "apache",
        "extensions": [
            "mid",
            "midi",
            "kar",
            "rmi"
        ]
    },
    "audio/mobile-xmf": {
        "source": "iana",
        "extensions": [
            "mxmf"
        ]
    },
    "audio/mp3": {
        "compressible": false,
        "extensions": [
            "mp3"
        ]
    },
    "audio/mp4": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "m4a",
            "mp4a"
        ]
    },
    "audio/mp4a-latm": {
        "source": "iana"
    },
    "audio/mpa": {
        "source": "iana"
    },
    "audio/mpa-robust": {
        "source": "iana"
    },
    "audio/mpeg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "mpga",
            "mp2",
            "mp2a",
            "mp3",
            "m2a",
            "m3a"
        ]
    },
    "audio/mpeg4-generic": {
        "source": "iana"
    },
    "audio/musepack": {
        "source": "apache"
    },
    "audio/ogg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "oga",
            "ogg",
            "spx",
            "opus"
        ]
    },
    "audio/opus": {
        "source": "iana"
    },
    "audio/parityfec": {
        "source": "iana"
    },
    "audio/pcma": {
        "source": "iana"
    },
    "audio/pcma-wb": {
        "source": "iana"
    },
    "audio/pcmu": {
        "source": "iana"
    },
    "audio/pcmu-wb": {
        "source": "iana"
    },
    "audio/prs.sid": {
        "source": "iana"
    },
    "audio/qcelp": {
        "source": "iana"
    },
    "audio/raptorfec": {
        "source": "iana"
    },
    "audio/red": {
        "source": "iana"
    },
    "audio/rtp-enc-aescm128": {
        "source": "iana"
    },
    "audio/rtp-midi": {
        "source": "iana"
    },
    "audio/rtploopback": {
        "source": "iana"
    },
    "audio/rtx": {
        "source": "iana"
    },
    "audio/s3m": {
        "source": "apache",
        "extensions": [
            "s3m"
        ]
    },
    "audio/scip": {
        "source": "iana"
    },
    "audio/silk": {
        "source": "apache",
        "extensions": [
            "sil"
        ]
    },
    "audio/smv": {
        "source": "iana"
    },
    "audio/smv-qcp": {
        "source": "iana"
    },
    "audio/smv0": {
        "source": "iana"
    },
    "audio/sofa": {
        "source": "iana"
    },
    "audio/sp-midi": {
        "source": "iana"
    },
    "audio/speex": {
        "source": "iana"
    },
    "audio/t140c": {
        "source": "iana"
    },
    "audio/t38": {
        "source": "iana"
    },
    "audio/telephone-event": {
        "source": "iana"
    },
    "audio/tetra_acelp": {
        "source": "iana"
    },
    "audio/tetra_acelp_bb": {
        "source": "iana"
    },
    "audio/tone": {
        "source": "iana"
    },
    "audio/tsvcis": {
        "source": "iana"
    },
    "audio/uemclip": {
        "source": "iana"
    },
    "audio/ulpfec": {
        "source": "iana"
    },
    "audio/usac": {
        "source": "iana"
    },
    "audio/vdvi": {
        "source": "iana"
    },
    "audio/vmr-wb": {
        "source": "iana"
    },
    "audio/vnd.3gpp.iufp": {
        "source": "iana"
    },
    "audio/vnd.4sb": {
        "source": "iana"
    },
    "audio/vnd.audiokoz": {
        "source": "iana"
    },
    "audio/vnd.celp": {
        "source": "iana"
    },
    "audio/vnd.cisco.nse": {
        "source": "iana"
    },
    "audio/vnd.cmles.radio-events": {
        "source": "iana"
    },
    "audio/vnd.cns.anp1": {
        "source": "iana"
    },
    "audio/vnd.cns.inf1": {
        "source": "iana"
    },
    "audio/vnd.dece.audio": {
        "source": "iana",
        "extensions": [
            "uva",
            "uvva"
        ]
    },
    "audio/vnd.digital-winds": {
        "source": "iana",
        "extensions": [
            "eol"
        ]
    },
    "audio/vnd.dlna.adts": {
        "source": "iana"
    },
    "audio/vnd.dolby.heaac.1": {
        "source": "iana"
    },
    "audio/vnd.dolby.heaac.2": {
        "source": "iana"
    },
    "audio/vnd.dolby.mlp": {
        "source": "iana"
    },
    "audio/vnd.dolby.mps": {
        "source": "iana"
    },
    "audio/vnd.dolby.pl2": {
        "source": "iana"
    },
    "audio/vnd.dolby.pl2x": {
        "source": "iana"
    },
    "audio/vnd.dolby.pl2z": {
        "source": "iana"
    },
    "audio/vnd.dolby.pulse.1": {
        "source": "iana"
    },
    "audio/vnd.dra": {
        "source": "iana",
        "extensions": [
            "dra"
        ]
    },
    "audio/vnd.dts": {
        "source": "iana",
        "extensions": [
            "dts"
        ]
    },
    "audio/vnd.dts.hd": {
        "source": "iana",
        "extensions": [
            "dtshd"
        ]
    },
    "audio/vnd.dts.uhd": {
        "source": "iana"
    },
    "audio/vnd.dvb.file": {
        "source": "iana"
    },
    "audio/vnd.everad.plj": {
        "source": "iana"
    },
    "audio/vnd.hns.audio": {
        "source": "iana"
    },
    "audio/vnd.lucent.voice": {
        "source": "iana",
        "extensions": [
            "lvp"
        ]
    },
    "audio/vnd.ms-playready.media.pya": {
        "source": "iana",
        "extensions": [
            "pya"
        ]
    },
    "audio/vnd.nokia.mobile-xmf": {
        "source": "iana"
    },
    "audio/vnd.nortel.vbk": {
        "source": "iana"
    },
    "audio/vnd.nuera.ecelp4800": {
        "source": "iana",
        "extensions": [
            "ecelp4800"
        ]
    },
    "audio/vnd.nuera.ecelp7470": {
        "source": "iana",
        "extensions": [
            "ecelp7470"
        ]
    },
    "audio/vnd.nuera.ecelp9600": {
        "source": "iana",
        "extensions": [
            "ecelp9600"
        ]
    },
    "audio/vnd.octel.sbc": {
        "source": "iana"
    },
    "audio/vnd.presonus.multitrack": {
        "source": "iana"
    },
    "audio/vnd.qcelp": {
        "source": "iana"
    },
    "audio/vnd.rhetorex.32kadpcm": {
        "source": "iana"
    },
    "audio/vnd.rip": {
        "source": "iana",
        "extensions": [
            "rip"
        ]
    },
    "audio/vnd.rn-realaudio": {
        "compressible": false
    },
    "audio/vnd.sealedmedia.softseal.mpeg": {
        "source": "iana"
    },
    "audio/vnd.vmx.cvsd": {
        "source": "iana"
    },
    "audio/vnd.wave": {
        "compressible": false
    },
    "audio/vorbis": {
        "source": "iana",
        "compressible": false
    },
    "audio/vorbis-config": {
        "source": "iana"
    },
    "audio/wav": {
        "compressible": false,
        "extensions": [
            "wav"
        ]
    },
    "audio/wave": {
        "compressible": false,
        "extensions": [
            "wav"
        ]
    },
    "audio/webm": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "weba"
        ]
    },
    "audio/x-aac": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "aac"
        ]
    },
    "audio/x-aiff": {
        "source": "apache",
        "extensions": [
            "aif",
            "aiff",
            "aifc"
        ]
    },
    "audio/x-caf": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "caf"
        ]
    },
    "audio/x-flac": {
        "source": "apache",
        "extensions": [
            "flac"
        ]
    },
    "audio/x-m4a": {
        "source": "nginx",
        "extensions": [
            "m4a"
        ]
    },
    "audio/x-matroska": {
        "source": "apache",
        "extensions": [
            "mka"
        ]
    },
    "audio/x-mpegurl": {
        "source": "apache",
        "extensions": [
            "m3u"
        ]
    },
    "audio/x-ms-wax": {
        "source": "apache",
        "extensions": [
            "wax"
        ]
    },
    "audio/x-ms-wma": {
        "source": "apache",
        "extensions": [
            "wma"
        ]
    },
    "audio/x-pn-realaudio": {
        "source": "apache",
        "extensions": [
            "ram",
            "ra"
        ]
    },
    "audio/x-pn-realaudio-plugin": {
        "source": "apache",
        "extensions": [
            "rmp"
        ]
    },
    "audio/x-realaudio": {
        "source": "nginx",
        "extensions": [
            "ra"
        ]
    },
    "audio/x-tta": {
        "source": "apache"
    },
    "audio/x-wav": {
        "source": "apache",
        "extensions": [
            "wav"
        ]
    },
    "audio/xm": {
        "source": "apache",
        "extensions": [
            "xm"
        ]
    },
    "chemical/x-cdx": {
        "source": "apache",
        "extensions": [
            "cdx"
        ]
    },
    "chemical/x-cif": {
        "source": "apache",
        "extensions": [
            "cif"
        ]
    },
    "chemical/x-cmdf": {
        "source": "apache",
        "extensions": [
            "cmdf"
        ]
    },
    "chemical/x-cml": {
        "source": "apache",
        "extensions": [
            "cml"
        ]
    },
    "chemical/x-csml": {
        "source": "apache",
        "extensions": [
            "csml"
        ]
    },
    "chemical/x-pdb": {
        "source": "apache"
    },
    "chemical/x-xyz": {
        "source": "apache",
        "extensions": [
            "xyz"
        ]
    },
    "font/collection": {
        "source": "iana",
        "extensions": [
            "ttc"
        ]
    },
    "font/otf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "otf"
        ]
    },
    "font/sfnt": {
        "source": "iana"
    },
    "font/ttf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ttf"
        ]
    },
    "font/woff": {
        "source": "iana",
        "extensions": [
            "woff"
        ]
    },
    "font/woff2": {
        "source": "iana",
        "extensions": [
            "woff2"
        ]
    },
    "image/aces": {
        "source": "iana",
        "extensions": [
            "exr"
        ]
    },
    "image/apng": {
        "compressible": false,
        "extensions": [
            "apng"
        ]
    },
    "image/avci": {
        "source": "iana",
        "extensions": [
            "avci"
        ]
    },
    "image/avcs": {
        "source": "iana",
        "extensions": [
            "avcs"
        ]
    },
    "image/avif": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "avif"
        ]
    },
    "image/bmp": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "bmp"
        ]
    },
    "image/cgm": {
        "source": "iana",
        "extensions": [
            "cgm"
        ]
    },
    "image/dicom-rle": {
        "source": "iana",
        "extensions": [
            "drle"
        ]
    },
    "image/emf": {
        "source": "iana",
        "extensions": [
            "emf"
        ]
    },
    "image/fits": {
        "source": "iana",
        "extensions": [
            "fits"
        ]
    },
    "image/g3fax": {
        "source": "iana",
        "extensions": [
            "g3"
        ]
    },
    "image/gif": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "gif"
        ]
    },
    "image/heic": {
        "source": "iana",
        "extensions": [
            "heic"
        ]
    },
    "image/heic-sequence": {
        "source": "iana",
        "extensions": [
            "heics"
        ]
    },
    "image/heif": {
        "source": "iana",
        "extensions": [
            "heif"
        ]
    },
    "image/heif-sequence": {
        "source": "iana",
        "extensions": [
            "heifs"
        ]
    },
    "image/hej2k": {
        "source": "iana",
        "extensions": [
            "hej2"
        ]
    },
    "image/hsj2": {
        "source": "iana",
        "extensions": [
            "hsj2"
        ]
    },
    "image/ief": {
        "source": "iana",
        "extensions": [
            "ief"
        ]
    },
    "image/jls": {
        "source": "iana",
        "extensions": [
            "jls"
        ]
    },
    "image/jp2": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jp2",
            "jpg2"
        ]
    },
    "image/jpeg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jpeg",
            "jpg",
            "jpe"
        ]
    },
    "image/jph": {
        "source": "iana",
        "extensions": [
            "jph"
        ]
    },
    "image/jphc": {
        "source": "iana",
        "extensions": [
            "jhc"
        ]
    },
    "image/jpm": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jpm"
        ]
    },
    "image/jpx": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jpx",
            "jpf"
        ]
    },
    "image/jxr": {
        "source": "iana",
        "extensions": [
            "jxr"
        ]
    },
    "image/jxra": {
        "source": "iana",
        "extensions": [
            "jxra"
        ]
    },
    "image/jxrs": {
        "source": "iana",
        "extensions": [
            "jxrs"
        ]
    },
    "image/jxs": {
        "source": "iana",
        "extensions": [
            "jxs"
        ]
    },
    "image/jxsc": {
        "source": "iana",
        "extensions": [
            "jxsc"
        ]
    },
    "image/jxsi": {
        "source": "iana",
        "extensions": [
            "jxsi"
        ]
    },
    "image/jxss": {
        "source": "iana",
        "extensions": [
            "jxss"
        ]
    },
    "image/ktx": {
        "source": "iana",
        "extensions": [
            "ktx"
        ]
    },
    "image/ktx2": {
        "source": "iana",
        "extensions": [
            "ktx2"
        ]
    },
    "image/naplps": {
        "source": "iana"
    },
    "image/pjpeg": {
        "compressible": false
    },
    "image/png": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "png"
        ]
    },
    "image/prs.btif": {
        "source": "iana",
        "extensions": [
            "btif"
        ]
    },
    "image/prs.pti": {
        "source": "iana",
        "extensions": [
            "pti"
        ]
    },
    "image/pwg-raster": {
        "source": "iana"
    },
    "image/sgi": {
        "source": "apache",
        "extensions": [
            "sgi"
        ]
    },
    "image/svg+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "svg",
            "svgz"
        ]
    },
    "image/t38": {
        "source": "iana",
        "extensions": [
            "t38"
        ]
    },
    "image/tiff": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "tif",
            "tiff"
        ]
    },
    "image/tiff-fx": {
        "source": "iana",
        "extensions": [
            "tfx"
        ]
    },
    "image/vnd.adobe.photoshop": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "psd"
        ]
    },
    "image/vnd.airzip.accelerator.azv": {
        "source": "iana",
        "extensions": [
            "azv"
        ]
    },
    "image/vnd.cns.inf2": {
        "source": "iana"
    },
    "image/vnd.dece.graphic": {
        "source": "iana",
        "extensions": [
            "uvi",
            "uvvi",
            "uvg",
            "uvvg"
        ]
    },
    "image/vnd.djvu": {
        "source": "iana",
        "extensions": [
            "djvu",
            "djv"
        ]
    },
    "image/vnd.dvb.subtitle": {
        "source": "iana",
        "extensions": [
            "sub"
        ]
    },
    "image/vnd.dwg": {
        "source": "iana",
        "extensions": [
            "dwg"
        ]
    },
    "image/vnd.dxf": {
        "source": "iana",
        "extensions": [
            "dxf"
        ]
    },
    "image/vnd.fastbidsheet": {
        "source": "iana",
        "extensions": [
            "fbs"
        ]
    },
    "image/vnd.fpx": {
        "source": "iana",
        "extensions": [
            "fpx"
        ]
    },
    "image/vnd.fst": {
        "source": "iana",
        "extensions": [
            "fst"
        ]
    },
    "image/vnd.fujixerox.edmics-mmr": {
        "source": "iana",
        "extensions": [
            "mmr"
        ]
    },
    "image/vnd.fujixerox.edmics-rlc": {
        "source": "iana",
        "extensions": [
            "rlc"
        ]
    },
    "image/vnd.globalgraphics.pgb": {
        "source": "iana"
    },
    "image/vnd.microsoft.icon": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ico"
        ]
    },
    "image/vnd.mix": {
        "source": "iana"
    },
    "image/vnd.mozilla.apng": {
        "source": "iana"
    },
    "image/vnd.ms-dds": {
        "compressible": true,
        "extensions": [
            "dds"
        ]
    },
    "image/vnd.ms-modi": {
        "source": "iana",
        "extensions": [
            "mdi"
        ]
    },
    "image/vnd.ms-photo": {
        "source": "apache",
        "extensions": [
            "wdp"
        ]
    },
    "image/vnd.net-fpx": {
        "source": "iana",
        "extensions": [
            "npx"
        ]
    },
    "image/vnd.pco.b16": {
        "source": "iana",
        "extensions": [
            "b16"
        ]
    },
    "image/vnd.radiance": {
        "source": "iana"
    },
    "image/vnd.sealed.png": {
        "source": "iana"
    },
    "image/vnd.sealedmedia.softseal.gif": {
        "source": "iana"
    },
    "image/vnd.sealedmedia.softseal.jpg": {
        "source": "iana"
    },
    "image/vnd.svf": {
        "source": "iana"
    },
    "image/vnd.tencent.tap": {
        "source": "iana",
        "extensions": [
            "tap"
        ]
    },
    "image/vnd.valve.source.texture": {
        "source": "iana",
        "extensions": [
            "vtf"
        ]
    },
    "image/vnd.wap.wbmp": {
        "source": "iana",
        "extensions": [
            "wbmp"
        ]
    },
    "image/vnd.xiff": {
        "source": "iana",
        "extensions": [
            "xif"
        ]
    },
    "image/vnd.zbrush.pcx": {
        "source": "iana",
        "extensions": [
            "pcx"
        ]
    },
    "image/webp": {
        "source": "apache",
        "extensions": [
            "webp"
        ]
    },
    "image/wmf": {
        "source": "iana",
        "extensions": [
            "wmf"
        ]
    },
    "image/x-3ds": {
        "source": "apache",
        "extensions": [
            "3ds"
        ]
    },
    "image/x-cmu-raster": {
        "source": "apache",
        "extensions": [
            "ras"
        ]
    },
    "image/x-cmx": {
        "source": "apache",
        "extensions": [
            "cmx"
        ]
    },
    "image/x-freehand": {
        "source": "apache",
        "extensions": [
            "fh",
            "fhc",
            "fh4",
            "fh5",
            "fh7"
        ]
    },
    "image/x-icon": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "ico"
        ]
    },
    "image/x-jng": {
        "source": "nginx",
        "extensions": [
            "jng"
        ]
    },
    "image/x-mrsid-image": {
        "source": "apache",
        "extensions": [
            "sid"
        ]
    },
    "image/x-ms-bmp": {
        "source": "nginx",
        "compressible": true,
        "extensions": [
            "bmp"
        ]
    },
    "image/x-pcx": {
        "source": "apache",
        "extensions": [
            "pcx"
        ]
    },
    "image/x-pict": {
        "source": "apache",
        "extensions": [
            "pic",
            "pct"
        ]
    },
    "image/x-portable-anymap": {
        "source": "apache",
        "extensions": [
            "pnm"
        ]
    },
    "image/x-portable-bitmap": {
        "source": "apache",
        "extensions": [
            "pbm"
        ]
    },
    "image/x-portable-graymap": {
        "source": "apache",
        "extensions": [
            "pgm"
        ]
    },
    "image/x-portable-pixmap": {
        "source": "apache",
        "extensions": [
            "ppm"
        ]
    },
    "image/x-rgb": {
        "source": "apache",
        "extensions": [
            "rgb"
        ]
    },
    "image/x-tga": {
        "source": "apache",
        "extensions": [
            "tga"
        ]
    },
    "image/x-xbitmap": {
        "source": "apache",
        "extensions": [
            "xbm"
        ]
    },
    "image/x-xcf": {
        "compressible": false
    },
    "image/x-xpixmap": {
        "source": "apache",
        "extensions": [
            "xpm"
        ]
    },
    "image/x-xwindowdump": {
        "source": "apache",
        "extensions": [
            "xwd"
        ]
    },
    "message/cpim": {
        "source": "iana"
    },
    "message/delivery-status": {
        "source": "iana"
    },
    "message/disposition-notification": {
        "source": "iana",
        "extensions": [
            "disposition-notification"
        ]
    },
    "message/external-body": {
        "source": "iana"
    },
    "message/feedback-report": {
        "source": "iana"
    },
    "message/global": {
        "source": "iana",
        "extensions": [
            "u8msg"
        ]
    },
    "message/global-delivery-status": {
        "source": "iana",
        "extensions": [
            "u8dsn"
        ]
    },
    "message/global-disposition-notification": {
        "source": "iana",
        "extensions": [
            "u8mdn"
        ]
    },
    "message/global-headers": {
        "source": "iana",
        "extensions": [
            "u8hdr"
        ]
    },
    "message/http": {
        "source": "iana",
        "compressible": false
    },
    "message/imdn+xml": {
        "source": "iana",
        "compressible": true
    },
    "message/news": {
        "source": "iana"
    },
    "message/partial": {
        "source": "iana",
        "compressible": false
    },
    "message/rfc822": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "eml",
            "mime"
        ]
    },
    "message/s-http": {
        "source": "iana"
    },
    "message/sip": {
        "source": "iana"
    },
    "message/sipfrag": {
        "source": "iana"
    },
    "message/tracking-status": {
        "source": "iana"
    },
    "message/vnd.si.simp": {
        "source": "iana"
    },
    "message/vnd.wfa.wsc": {
        "source": "iana",
        "extensions": [
            "wsc"
        ]
    },
    "model/3mf": {
        "source": "iana",
        "extensions": [
            "3mf"
        ]
    },
    "model/e57": {
        "source": "iana"
    },
    "model/gltf+json": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "gltf"
        ]
    },
    "model/gltf-binary": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "glb"
        ]
    },
    "model/iges": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "igs",
            "iges"
        ]
    },
    "model/mesh": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "msh",
            "mesh",
            "silo"
        ]
    },
    "model/mtl": {
        "source": "iana",
        "extensions": [
            "mtl"
        ]
    },
    "model/obj": {
        "source": "iana",
        "extensions": [
            "obj"
        ]
    },
    "model/step": {
        "source": "iana"
    },
    "model/step+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "stpx"
        ]
    },
    "model/step+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "stpz"
        ]
    },
    "model/step-xml+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "stpxz"
        ]
    },
    "model/stl": {
        "source": "iana",
        "extensions": [
            "stl"
        ]
    },
    "model/vnd.collada+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dae"
        ]
    },
    "model/vnd.dwf": {
        "source": "iana",
        "extensions": [
            "dwf"
        ]
    },
    "model/vnd.flatland.3dml": {
        "source": "iana"
    },
    "model/vnd.gdl": {
        "source": "iana",
        "extensions": [
            "gdl"
        ]
    },
    "model/vnd.gs-gdl": {
        "source": "apache"
    },
    "model/vnd.gs.gdl": {
        "source": "iana"
    },
    "model/vnd.gtw": {
        "source": "iana",
        "extensions": [
            "gtw"
        ]
    },
    "model/vnd.moml+xml": {
        "source": "iana",
        "compressible": true
    },
    "model/vnd.mts": {
        "source": "iana",
        "extensions": [
            "mts"
        ]
    },
    "model/vnd.opengex": {
        "source": "iana",
        "extensions": [
            "ogex"
        ]
    },
    "model/vnd.parasolid.transmit.binary": {
        "source": "iana",
        "extensions": [
            "x_b"
        ]
    },
    "model/vnd.parasolid.transmit.text": {
        "source": "iana",
        "extensions": [
            "x_t"
        ]
    },
    "model/vnd.pytha.pyox": {
        "source": "iana"
    },
    "model/vnd.rosette.annotated-data-model": {
        "source": "iana"
    },
    "model/vnd.sap.vds": {
        "source": "iana",
        "extensions": [
            "vds"
        ]
    },
    "model/vnd.usdz+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "usdz"
        ]
    },
    "model/vnd.valve.source.compiled-map": {
        "source": "iana",
        "extensions": [
            "bsp"
        ]
    },
    "model/vnd.vtu": {
        "source": "iana",
        "extensions": [
            "vtu"
        ]
    },
    "model/vrml": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "wrl",
            "vrml"
        ]
    },
    "model/x3d+binary": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "x3db",
            "x3dbz"
        ]
    },
    "model/x3d+fastinfoset": {
        "source": "iana",
        "extensions": [
            "x3db"
        ]
    },
    "model/x3d+vrml": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "x3dv",
            "x3dvz"
        ]
    },
    "model/x3d+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "x3d",
            "x3dz"
        ]
    },
    "model/x3d-vrml": {
        "source": "iana",
        "extensions": [
            "x3dv"
        ]
    },
    "multipart/alternative": {
        "source": "iana",
        "compressible": false
    },
    "multipart/appledouble": {
        "source": "iana"
    },
    "multipart/byteranges": {
        "source": "iana"
    },
    "multipart/digest": {
        "source": "iana"
    },
    "multipart/encrypted": {
        "source": "iana",
        "compressible": false
    },
    "multipart/form-data": {
        "source": "iana",
        "compressible": false
    },
    "multipart/header-set": {
        "source": "iana"
    },
    "multipart/mixed": {
        "source": "iana"
    },
    "multipart/multilingual": {
        "source": "iana"
    },
    "multipart/parallel": {
        "source": "iana"
    },
    "multipart/related": {
        "source": "iana",
        "compressible": false
    },
    "multipart/report": {
        "source": "iana"
    },
    "multipart/signed": {
        "source": "iana",
        "compressible": false
    },
    "multipart/vnd.bint.med-plus": {
        "source": "iana"
    },
    "multipart/voice-message": {
        "source": "iana"
    },
    "multipart/x-mixed-replace": {
        "source": "iana"
    },
    "text/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "text/cache-manifest": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "appcache",
            "manifest"
        ]
    },
    "text/calendar": {
        "source": "iana",
        "extensions": [
            "ics",
            "ifb"
        ]
    },
    "text/calender": {
        "compressible": true
    },
    "text/cmd": {
        "compressible": true
    },
    "text/coffeescript": {
        "extensions": [
            "coffee",
            "litcoffee"
        ]
    },
    "text/cql": {
        "source": "iana"
    },
    "text/cql-expression": {
        "source": "iana"
    },
    "text/cql-identifier": {
        "source": "iana"
    },
    "text/css": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "css"
        ]
    },
    "text/csv": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "csv"
        ]
    },
    "text/csv-schema": {
        "source": "iana"
    },
    "text/directory": {
        "source": "iana"
    },
    "text/dns": {
        "source": "iana"
    },
    "text/ecmascript": {
        "source": "iana"
    },
    "text/encaprtp": {
        "source": "iana"
    },
    "text/enriched": {
        "source": "iana"
    },
    "text/fhirpath": {
        "source": "iana"
    },
    "text/flexfec": {
        "source": "iana"
    },
    "text/fwdred": {
        "source": "iana"
    },
    "text/gff3": {
        "source": "iana"
    },
    "text/grammar-ref-list": {
        "source": "iana"
    },
    "text/html": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "html",
            "htm",
            "shtml"
        ]
    },
    "text/jade": {
        "extensions": [
            "jade"
        ]
    },
    "text/javascript": {
        "source": "iana",
        "compressible": true
    },
    "text/jcr-cnd": {
        "source": "iana"
    },
    "text/jsx": {
        "compressible": true,
        "extensions": [
            "jsx"
        ]
    },
    "text/less": {
        "compressible": true,
        "extensions": [
            "less"
        ]
    },
    "text/markdown": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "markdown",
            "md"
        ]
    },
    "text/mathml": {
        "source": "nginx",
        "extensions": [
            "mml"
        ]
    },
    "text/mdx": {
        "compressible": true,
        "extensions": [
            "mdx"
        ]
    },
    "text/mizar": {
        "source": "iana"
    },
    "text/n3": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "n3"
        ]
    },
    "text/parameters": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/parityfec": {
        "source": "iana"
    },
    "text/plain": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "txt",
            "text",
            "conf",
            "def",
            "list",
            "log",
            "in",
            "ini"
        ]
    },
    "text/provenance-notation": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/prs.fallenstein.rst": {
        "source": "iana"
    },
    "text/prs.lines.tag": {
        "source": "iana",
        "extensions": [
            "dsc"
        ]
    },
    "text/prs.prop.logic": {
        "source": "iana"
    },
    "text/raptorfec": {
        "source": "iana"
    },
    "text/red": {
        "source": "iana"
    },
    "text/rfc822-headers": {
        "source": "iana"
    },
    "text/richtext": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rtx"
        ]
    },
    "text/rtf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rtf"
        ]
    },
    "text/rtp-enc-aescm128": {
        "source": "iana"
    },
    "text/rtploopback": {
        "source": "iana"
    },
    "text/rtx": {
        "source": "iana"
    },
    "text/sgml": {
        "source": "iana",
        "extensions": [
            "sgml",
            "sgm"
        ]
    },
    "text/shaclc": {
        "source": "iana"
    },
    "text/shex": {
        "source": "iana",
        "extensions": [
            "shex"
        ]
    },
    "text/slim": {
        "extensions": [
            "slim",
            "slm"
        ]
    },
    "text/spdx": {
        "source": "iana",
        "extensions": [
            "spdx"
        ]
    },
    "text/strings": {
        "source": "iana"
    },
    "text/stylus": {
        "extensions": [
            "stylus",
            "styl"
        ]
    },
    "text/t140": {
        "source": "iana"
    },
    "text/tab-separated-values": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "tsv"
        ]
    },
    "text/troff": {
        "source": "iana",
        "extensions": [
            "t",
            "tr",
            "roff",
            "man",
            "me",
            "ms"
        ]
    },
    "text/turtle": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "ttl"
        ]
    },
    "text/ulpfec": {
        "source": "iana"
    },
    "text/uri-list": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "uri",
            "uris",
            "urls"
        ]
    },
    "text/vcard": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "vcard"
        ]
    },
    "text/vnd.a": {
        "source": "iana"
    },
    "text/vnd.abc": {
        "source": "iana"
    },
    "text/vnd.ascii-art": {
        "source": "iana"
    },
    "text/vnd.curl": {
        "source": "iana",
        "extensions": [
            "curl"
        ]
    },
    "text/vnd.curl.dcurl": {
        "source": "apache",
        "extensions": [
            "dcurl"
        ]
    },
    "text/vnd.curl.mcurl": {
        "source": "apache",
        "extensions": [
            "mcurl"
        ]
    },
    "text/vnd.curl.scurl": {
        "source": "apache",
        "extensions": [
            "scurl"
        ]
    },
    "text/vnd.debian.copyright": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/vnd.dmclientscript": {
        "source": "iana"
    },
    "text/vnd.dvb.subtitle": {
        "source": "iana",
        "extensions": [
            "sub"
        ]
    },
    "text/vnd.esmertec.theme-descriptor": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/vnd.familysearch.gedcom": {
        "source": "iana",
        "extensions": [
            "ged"
        ]
    },
    "text/vnd.ficlab.flt": {
        "source": "iana"
    },
    "text/vnd.fly": {
        "source": "iana",
        "extensions": [
            "fly"
        ]
    },
    "text/vnd.fmi.flexstor": {
        "source": "iana",
        "extensions": [
            "flx"
        ]
    },
    "text/vnd.gml": {
        "source": "iana"
    },
    "text/vnd.graphviz": {
        "source": "iana",
        "extensions": [
            "gv"
        ]
    },
    "text/vnd.hans": {
        "source": "iana"
    },
    "text/vnd.hgl": {
        "source": "iana"
    },
    "text/vnd.in3d.3dml": {
        "source": "iana",
        "extensions": [
            "3dml"
        ]
    },
    "text/vnd.in3d.spot": {
        "source": "iana",
        "extensions": [
            "spot"
        ]
    },
    "text/vnd.iptc.newsml": {
        "source": "iana"
    },
    "text/vnd.iptc.nitf": {
        "source": "iana"
    },
    "text/vnd.latex-z": {
        "source": "iana"
    },
    "text/vnd.motorola.reflex": {
        "source": "iana"
    },
    "text/vnd.ms-mediapackage": {
        "source": "iana"
    },
    "text/vnd.net2phone.commcenter.command": {
        "source": "iana"
    },
    "text/vnd.radisys.msml-basic-layout": {
        "source": "iana"
    },
    "text/vnd.senx.warpscript": {
        "source": "iana"
    },
    "text/vnd.si.uricatalogue": {
        "source": "iana"
    },
    "text/vnd.sosi": {
        "source": "iana"
    },
    "text/vnd.sun.j2me.app-descriptor": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "jad"
        ]
    },
    "text/vnd.trolltech.linguist": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/vnd.wap.si": {
        "source": "iana"
    },
    "text/vnd.wap.sl": {
        "source": "iana"
    },
    "text/vnd.wap.wml": {
        "source": "iana",
        "extensions": [
            "wml"
        ]
    },
    "text/vnd.wap.wmlscript": {
        "source": "iana",
        "extensions": [
            "wmls"
        ]
    },
    "text/vtt": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "vtt"
        ]
    },
    "text/x-asm": {
        "source": "apache",
        "extensions": [
            "s",
            "asm"
        ]
    },
    "text/x-c": {
        "source": "apache",
        "extensions": [
            "c",
            "cc",
            "cxx",
            "cpp",
            "h",
            "hh",
            "dic"
        ]
    },
    "text/x-component": {
        "source": "nginx",
        "extensions": [
            "htc"
        ]
    },
    "text/x-fortran": {
        "source": "apache",
        "extensions": [
            "f",
            "for",
            "f77",
            "f90"
        ]
    },
    "text/x-gwt-rpc": {
        "compressible": true
    },
    "text/x-handlebars-template": {
        "extensions": [
            "hbs"
        ]
    },
    "text/x-java-source": {
        "source": "apache",
        "extensions": [
            "java"
        ]
    },
    "text/x-jquery-tmpl": {
        "compressible": true
    },
    "text/x-lua": {
        "extensions": [
            "lua"
        ]
    },
    "text/x-markdown": {
        "compressible": true,
        "extensions": [
            "mkd"
        ]
    },
    "text/x-nfo": {
        "source": "apache",
        "extensions": [
            "nfo"
        ]
    },
    "text/x-opml": {
        "source": "apache",
        "extensions": [
            "opml"
        ]
    },
    "text/x-org": {
        "compressible": true,
        "extensions": [
            "org"
        ]
    },
    "text/x-pascal": {
        "source": "apache",
        "extensions": [
            "p",
            "pas"
        ]
    },
    "text/x-processing": {
        "compressible": true,
        "extensions": [
            "pde"
        ]
    },
    "text/x-sass": {
        "extensions": [
            "sass"
        ]
    },
    "text/x-scss": {
        "extensions": [
            "scss"
        ]
    },
    "text/x-setext": {
        "source": "apache",
        "extensions": [
            "etx"
        ]
    },
    "text/x-sfv": {
        "source": "apache",
        "extensions": [
            "sfv"
        ]
    },
    "text/x-suse-ymp": {
        "compressible": true,
        "extensions": [
            "ymp"
        ]
    },
    "text/x-uuencode": {
        "source": "apache",
        "extensions": [
            "uu"
        ]
    },
    "text/x-vcalendar": {
        "source": "apache",
        "extensions": [
            "vcs"
        ]
    },
    "text/x-vcard": {
        "source": "apache",
        "extensions": [
            "vcf"
        ]
    },
    "text/xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xml"
        ]
    },
    "text/xml-external-parsed-entity": {
        "source": "iana"
    },
    "text/yaml": {
        "compressible": true,
        "extensions": [
            "yaml",
            "yml"
        ]
    },
    "video/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "video/3gpp": {
        "source": "iana",
        "extensions": [
            "3gp",
            "3gpp"
        ]
    },
    "video/3gpp-tt": {
        "source": "iana"
    },
    "video/3gpp2": {
        "source": "iana",
        "extensions": [
            "3g2"
        ]
    },
    "video/av1": {
        "source": "iana"
    },
    "video/bmpeg": {
        "source": "iana"
    },
    "video/bt656": {
        "source": "iana"
    },
    "video/celb": {
        "source": "iana"
    },
    "video/dv": {
        "source": "iana"
    },
    "video/encaprtp": {
        "source": "iana"
    },
    "video/ffv1": {
        "source": "iana"
    },
    "video/flexfec": {
        "source": "iana"
    },
    "video/h261": {
        "source": "iana",
        "extensions": [
            "h261"
        ]
    },
    "video/h263": {
        "source": "iana",
        "extensions": [
            "h263"
        ]
    },
    "video/h263-1998": {
        "source": "iana"
    },
    "video/h263-2000": {
        "source": "iana"
    },
    "video/h264": {
        "source": "iana",
        "extensions": [
            "h264"
        ]
    },
    "video/h264-rcdo": {
        "source": "iana"
    },
    "video/h264-svc": {
        "source": "iana"
    },
    "video/h265": {
        "source": "iana"
    },
    "video/iso.segment": {
        "source": "iana",
        "extensions": [
            "m4s"
        ]
    },
    "video/jpeg": {
        "source": "iana",
        "extensions": [
            "jpgv"
        ]
    },
    "video/jpeg2000": {
        "source": "iana"
    },
    "video/jpm": {
        "source": "apache",
        "extensions": [
            "jpm",
            "jpgm"
        ]
    },
    "video/jxsv": {
        "source": "iana"
    },
    "video/mj2": {
        "source": "iana",
        "extensions": [
            "mj2",
            "mjp2"
        ]
    },
    "video/mp1s": {
        "source": "iana"
    },
    "video/mp2p": {
        "source": "iana"
    },
    "video/mp2t": {
        "source": "iana",
        "extensions": [
            "ts"
        ]
    },
    "video/mp4": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "mp4",
            "mp4v",
            "mpg4"
        ]
    },
    "video/mp4v-es": {
        "source": "iana"
    },
    "video/mpeg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "mpeg",
            "mpg",
            "mpe",
            "m1v",
            "m2v"
        ]
    },
    "video/mpeg4-generic": {
        "source": "iana"
    },
    "video/mpv": {
        "source": "iana"
    },
    "video/nv": {
        "source": "iana"
    },
    "video/ogg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ogv"
        ]
    },
    "video/parityfec": {
        "source": "iana"
    },
    "video/pointer": {
        "source": "iana"
    },
    "video/quicktime": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "qt",
            "mov"
        ]
    },
    "video/raptorfec": {
        "source": "iana"
    },
    "video/raw": {
        "source": "iana"
    },
    "video/rtp-enc-aescm128": {
        "source": "iana"
    },
    "video/rtploopback": {
        "source": "iana"
    },
    "video/rtx": {
        "source": "iana"
    },
    "video/scip": {
        "source": "iana"
    },
    "video/smpte291": {
        "source": "iana"
    },
    "video/smpte292m": {
        "source": "iana"
    },
    "video/ulpfec": {
        "source": "iana"
    },
    "video/vc1": {
        "source": "iana"
    },
    "video/vc2": {
        "source": "iana"
    },
    "video/vnd.cctv": {
        "source": "iana"
    },
    "video/vnd.dece.hd": {
        "source": "iana",
        "extensions": [
            "uvh",
            "uvvh"
        ]
    },
    "video/vnd.dece.mobile": {
        "source": "iana",
        "extensions": [
            "uvm",
            "uvvm"
        ]
    },
    "video/vnd.dece.mp4": {
        "source": "iana"
    },
    "video/vnd.dece.pd": {
        "source": "iana",
        "extensions": [
            "uvp",
            "uvvp"
        ]
    },
    "video/vnd.dece.sd": {
        "source": "iana",
        "extensions": [
            "uvs",
            "uvvs"
        ]
    },
    "video/vnd.dece.video": {
        "source": "iana",
        "extensions": [
            "uvv",
            "uvvv"
        ]
    },
    "video/vnd.directv.mpeg": {
        "source": "iana"
    },
    "video/vnd.directv.mpeg-tts": {
        "source": "iana"
    },
    "video/vnd.dlna.mpeg-tts": {
        "source": "iana"
    },
    "video/vnd.dvb.file": {
        "source": "iana",
        "extensions": [
            "dvb"
        ]
    },
    "video/vnd.fvt": {
        "source": "iana",
        "extensions": [
            "fvt"
        ]
    },
    "video/vnd.hns.video": {
        "source": "iana"
    },
    "video/vnd.iptvforum.1dparityfec-1010": {
        "source": "iana"
    },
    "video/vnd.iptvforum.1dparityfec-2005": {
        "source": "iana"
    },
    "video/vnd.iptvforum.2dparityfec-1010": {
        "source": "iana"
    },
    "video/vnd.iptvforum.2dparityfec-2005": {
        "source": "iana"
    },
    "video/vnd.iptvforum.ttsavc": {
        "source": "iana"
    },
    "video/vnd.iptvforum.ttsmpeg2": {
        "source": "iana"
    },
    "video/vnd.motorola.video": {
        "source": "iana"
    },
    "video/vnd.motorola.videop": {
        "source": "iana"
    },
    "video/vnd.mpegurl": {
        "source": "iana",
        "extensions": [
            "mxu",
            "m4u"
        ]
    },
    "video/vnd.ms-playready.media.pyv": {
        "source": "iana",
        "extensions": [
            "pyv"
        ]
    },
    "video/vnd.nokia.interleaved-multimedia": {
        "source": "iana"
    },
    "video/vnd.nokia.mp4vr": {
        "source": "iana"
    },
    "video/vnd.nokia.videovoip": {
        "source": "iana"
    },
    "video/vnd.objectvideo": {
        "source": "iana"
    },
    "video/vnd.radgamettools.bink": {
        "source": "iana"
    },
    "video/vnd.radgamettools.smacker": {
        "source": "iana"
    },
    "video/vnd.sealed.mpeg1": {
        "source": "iana"
    },
    "video/vnd.sealed.mpeg4": {
        "source": "iana"
    },
    "video/vnd.sealed.swf": {
        "source": "iana"
    },
    "video/vnd.sealedmedia.softseal.mov": {
        "source": "iana"
    },
    "video/vnd.uvvu.mp4": {
        "source": "iana",
        "extensions": [
            "uvu",
            "uvvu"
        ]
    },
    "video/vnd.vivo": {
        "source": "iana",
        "extensions": [
            "viv"
        ]
    },
    "video/vnd.youtube.yt": {
        "source": "iana"
    },
    "video/vp8": {
        "source": "iana"
    },
    "video/vp9": {
        "source": "iana"
    },
    "video/webm": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "webm"
        ]
    },
    "video/x-f4v": {
        "source": "apache",
        "extensions": [
            "f4v"
        ]
    },
    "video/x-fli": {
        "source": "apache",
        "extensions": [
            "fli"
        ]
    },
    "video/x-flv": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "flv"
        ]
    },
    "video/x-m4v": {
        "source": "apache",
        "extensions": [
            "m4v"
        ]
    },
    "video/x-matroska": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "mkv",
            "mk3d",
            "mks"
        ]
    },
    "video/x-mng": {
        "source": "apache",
        "extensions": [
            "mng"
        ]
    },
    "video/x-ms-asf": {
        "source": "apache",
        "extensions": [
            "asf",
            "asx"
        ]
    },
    "video/x-ms-vob": {
        "source": "apache",
        "extensions": [
            "vob"
        ]
    },
    "video/x-ms-wm": {
        "source": "apache",
        "extensions": [
            "wm"
        ]
    },
    "video/x-ms-wmv": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "wmv"
        ]
    },
    "video/x-ms-wmx": {
        "source": "apache",
        "extensions": [
            "wmx"
        ]
    },
    "video/x-ms-wvx": {
        "source": "apache",
        "extensions": [
            "wvx"
        ]
    },
    "video/x-msvideo": {
        "source": "apache",
        "extensions": [
            "avi"
        ]
    },
    "video/x-sgi-movie": {
        "source": "apache",
        "extensions": [
            "movie"
        ]
    },
    "video/x-smv": {
        "source": "apache",
        "extensions": [
            "smv"
        ]
    },
    "x-conference/x-cooltalk": {
        "source": "apache",
        "extensions": [
            "ice"
        ]
    },
    "x-shader/x-fragment": {
        "compressible": true
    },
    "x-shader/x-vertex": {
        "compressible": true
    }
};
const types = new Map();
(function populateMaps() {
    const preference = [
        "nginx",
        "apache",
        undefined,
        "iana"
    ];
    for (const type of Object.keys(__default)){
        const mime = __default[type];
        const exts = mime.extensions;
        if (!exts || !exts.length) {
            continue;
        }
        extensions.set(type, exts);
        for (const ext of exts){
            const current = types.get(ext);
            if (current) {
                const from = preference.indexOf(__default[current].source);
                const to = preference.indexOf(mime.source);
                if (current !== "application/octet-stream" && (from > to || from === to && current.startsWith("application/"))) {
                    continue;
                }
            }
            types.set(ext, type);
        }
    }
})();
function typeByExtension(extension) {
    extension = extension.startsWith(".") ? extension.slice(1) : extension;
    return types.get(extension.toLowerCase());
}
function getCharset(type) {
    try {
        const [mediaType, params] = parseMediaType1(type);
        if (params && params["charset"]) {
            return params["charset"];
        }
        const entry = __default[mediaType];
        if (entry && entry.charset) {
            return entry.charset;
        }
        if (mediaType.startsWith("text/")) {
            return "UTF-8";
        }
    } catch  {}
    return undefined;
}
function formatMediaType(type, param) {
    let b = "";
    const [major, sub] = type.split("/");
    if (!sub) {
        if (!isToken(type)) {
            return "";
        }
        b += type.toLowerCase();
    } else {
        if (!isToken(major) || !isToken(sub)) {
            return "";
        }
        b += `${major.toLowerCase()}/${sub.toLowerCase()}`;
    }
    if (param) {
        param = isIterator(param) ? Object.fromEntries(param) : param;
        const attrs = Object.keys(param);
        attrs.sort();
        for (const attribute of attrs){
            if (!isToken(attribute)) {
                return "";
            }
            const value = param[attribute];
            b += `; ${attribute.toLowerCase()}`;
            const needEnc = needsEncoding(value);
            if (needEnc) {
                b += "*";
            }
            b += "=";
            if (needEnc) {
                b += `utf-8''${encodeURIComponent(value)}`;
                continue;
            }
            if (isToken(value)) {
                b += value;
                continue;
            }
            b += `"${value.replace(/["\\]/gi, (m)=>`\\${m}`)}"`;
        }
    }
    return b;
}
function contentType(extensionOrType) {
    try {
        const [mediaType, params = {}] = extensionOrType.includes("/") ? parseMediaType1(extensionOrType) : [
            typeByExtension(extensionOrType),
            undefined
        ];
        if (!mediaType) {
            return undefined;
        }
        if (!("charset" in params)) {
            const charset = getCharset(mediaType);
            if (charset) {
                params.charset = charset;
            }
        }
        return formatMediaType(mediaType, params);
    } catch  {}
    return undefined;
}
function extensionsByType(type) {
    try {
        const [mediaType] = parseMediaType1(type);
        return extensions.get(mediaType);
    } catch  {}
}
function extension(type) {
    const exts = extensionsByType(type);
    if (exts) {
        return exts[0];
    }
    return undefined;
}
const MAX_SIZE1 = 2 ** 32 - 2;
class Buffer1 {
    #buf;
    #off = 0;
    #readable = new ReadableStream({
        type: "bytes",
        pull: (controller)=>{
            const view = new Uint8Array(controller.byobRequest.view.buffer);
            if (this.empty()) {
                this.reset();
                controller.close();
                controller.byobRequest.respond(0);
                return;
            }
            const nread = copy(this.#buf.subarray(this.#off), view);
            this.#off += nread;
            controller.byobRequest.respond(nread);
        },
        autoAllocateChunkSize: 16_640
    });
    get readable() {
        return this.#readable;
    }
    #writable = new WritableStream({
        write: (chunk)=>{
            const m = this.#grow(chunk.byteLength);
            copy(chunk, this.#buf, m);
        }
    });
    get writable() {
        return this.#writable;
    }
    constructor(ab){
        this.#buf = ab === undefined ? new Uint8Array(0) : new Uint8Array(ab);
    }
    bytes(options = {
        copy: true
    }) {
        if (options.copy === false) return this.#buf.subarray(this.#off);
        return this.#buf.slice(this.#off);
    }
    empty() {
        return this.#buf.byteLength <= this.#off;
    }
    get length() {
        return this.#buf.byteLength - this.#off;
    }
    get capacity() {
        return this.#buf.buffer.byteLength;
    }
    truncate(n) {
        if (n === 0) {
            this.reset();
            return;
        }
        if (n < 0 || n > this.length) {
            throw Error("bytes.Buffer: truncation out of range");
        }
        this.#reslice(this.#off + n);
    }
    reset() {
        this.#reslice(0);
        this.#off = 0;
    }
    #tryGrowByReslice(n) {
        const l = this.#buf.byteLength;
        if (n <= this.capacity - l) {
            this.#reslice(l + n);
            return l;
        }
        return -1;
    }
    #reslice(len) {
        assert(len <= this.#buf.buffer.byteLength);
        this.#buf = new Uint8Array(this.#buf.buffer, 0, len);
    }
    #grow(n) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n <= Math.floor(c / 2) - m) {
            copy(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n > MAX_SIZE1) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE1));
            copy(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n, MAX_SIZE1));
        return m;
    }
    grow(n) {
        if (n < 0) {
            throw Error("Buffer.grow: negative count");
        }
        const m = this.#grow(n);
        this.#reslice(m);
    }
}
function createLPS(pat) {
    const lps = new Uint8Array(pat.length);
    lps[0] = 0;
    let prefixEnd = 0;
    let i = 1;
    while(i < lps.length){
        if (pat[i] == pat[prefixEnd]) {
            prefixEnd++;
            lps[i] = prefixEnd;
            i++;
        } else if (prefixEnd === 0) {
            lps[i] = 0;
            i++;
        } else {
            prefixEnd = lps[prefixEnd - 1];
        }
    }
    return lps;
}
class DelimiterStream extends TransformStream {
    #bufs = new BytesList();
    #delimiter;
    #inspectIndex = 0;
    #matchIndex = 0;
    #delimLen;
    #delimLPS;
    #disp;
    constructor(delimiter, options){
        super({
            transform: (chunk, controller)=>{
                this.#handle(chunk, controller);
            },
            flush: (controller)=>{
                controller.enqueue(this.#bufs.concat());
            }
        });
        this.#delimiter = delimiter;
        this.#delimLen = delimiter.length;
        this.#delimLPS = createLPS(delimiter);
        this.#disp = options?.disposition ?? "discard";
    }
    #handle(chunk, controller) {
        this.#bufs.add(chunk);
        let localIndex = 0;
        while(this.#inspectIndex < this.#bufs.size()){
            if (chunk[localIndex] === this.#delimiter[this.#matchIndex]) {
                this.#inspectIndex++;
                localIndex++;
                this.#matchIndex++;
                if (this.#matchIndex === this.#delimLen) {
                    const start = this.#inspectIndex - this.#delimLen;
                    const end = this.#disp == "suffix" ? this.#inspectIndex : start;
                    const copy = this.#bufs.slice(0, end);
                    controller.enqueue(copy);
                    const shift = this.#disp == "prefix" ? start : this.#inspectIndex;
                    this.#bufs.shift(shift);
                    this.#inspectIndex = this.#disp == "prefix" ? this.#delimLen : 0;
                    this.#matchIndex = 0;
                }
            } else {
                if (this.#matchIndex === 0) {
                    this.#inspectIndex++;
                    localIndex++;
                } else {
                    this.#matchIndex = this.#delimLPS[this.#matchIndex - 1];
                }
            }
        }
    }
}
async function readAll(r) {
    const buf = new Buffer();
    await buf.readFrom(r);
    return buf.bytes();
}
async function writeAll(w, arr) {
    let nwritten = 0;
    while(nwritten < arr.length){
        nwritten += await w.write(arr.subarray(nwritten));
    }
}
function readerFromStreamReader(streamReader) {
    const buffer = new Buffer();
    return {
        async read (p) {
            if (buffer.empty()) {
                const res = await streamReader.read();
                if (res.done) {
                    return null;
                }
                await writeAll(buffer, res.value);
            }
            return buffer.read(p);
        }
    };
}
const osType = (()=>{
    const { Deno: Deno1 } = globalThis;
    if (typeof Deno1?.build?.os === "string") {
        return Deno1.build.os;
    }
    const { navigator } = globalThis;
    if (navigator?.appVersion?.includes?.("Win")) {
        return "windows";
    }
    return "linux";
})();
const isWindows = osType === "windows";
const CHAR_FORWARD_SLASH = 47;
function assertPath(path) {
    if (typeof path !== "string") {
        throw new TypeError(`Path must be a string. Received ${JSON.stringify(path)}`);
    }
}
function isPosixPathSeparator(code) {
    return code === 47;
}
function isPathSeparator(code) {
    return isPosixPathSeparator(code) || code === 92;
}
function isWindowsDeviceRoot(code) {
    return code >= 97 && code <= 122 || code >= 65 && code <= 90;
}
function normalizeString(path, allowAboveRoot, separator, isPathSeparator) {
    let res = "";
    let lastSegmentLength = 0;
    let lastSlash = -1;
    let dots = 0;
    let code;
    for(let i = 0, len = path.length; i <= len; ++i){
        if (i < len) code = path.charCodeAt(i);
        else if (isPathSeparator(code)) break;
        else code = CHAR_FORWARD_SLASH;
        if (isPathSeparator(code)) {
            if (lastSlash === i - 1 || dots === 1) {} else if (lastSlash !== i - 1 && dots === 2) {
                if (res.length < 2 || lastSegmentLength !== 2 || res.charCodeAt(res.length - 1) !== 46 || res.charCodeAt(res.length - 2) !== 46) {
                    if (res.length > 2) {
                        const lastSlashIndex = res.lastIndexOf(separator);
                        if (lastSlashIndex === -1) {
                            res = "";
                            lastSegmentLength = 0;
                        } else {
                            res = res.slice(0, lastSlashIndex);
                            lastSegmentLength = res.length - 1 - res.lastIndexOf(separator);
                        }
                        lastSlash = i;
                        dots = 0;
                        continue;
                    } else if (res.length === 2 || res.length === 1) {
                        res = "";
                        lastSegmentLength = 0;
                        lastSlash = i;
                        dots = 0;
                        continue;
                    }
                }
                if (allowAboveRoot) {
                    if (res.length > 0) res += `${separator}..`;
                    else res = "..";
                    lastSegmentLength = 2;
                }
            } else {
                if (res.length > 0) res += separator + path.slice(lastSlash + 1, i);
                else res = path.slice(lastSlash + 1, i);
                lastSegmentLength = i - lastSlash - 1;
            }
            lastSlash = i;
            dots = 0;
        } else if (code === 46 && dots !== -1) {
            ++dots;
        } else {
            dots = -1;
        }
    }
    return res;
}
function _format(sep, pathObject) {
    const dir = pathObject.dir || pathObject.root;
    const base = pathObject.base || (pathObject.name || "") + (pathObject.ext || "");
    if (!dir) return base;
    if (base === sep) return dir;
    if (dir === pathObject.root) return dir + base;
    return dir + sep + base;
}
const WHITESPACE_ENCODINGS = {
    "\u0009": "%09",
    "\u000A": "%0A",
    "\u000B": "%0B",
    "\u000C": "%0C",
    "\u000D": "%0D",
    "\u0020": "%20"
};
function encodeWhitespace(string) {
    return string.replaceAll(/[\s]/g, (c)=>{
        return WHITESPACE_ENCODINGS[c] ?? c;
    });
}
function lastPathSegment(path, isSep, start = 0) {
    let matchedNonSeparator = false;
    let end = path.length;
    for(let i = path.length - 1; i >= start; --i){
        if (isSep(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                start = i + 1;
                break;
            }
        } else if (!matchedNonSeparator) {
            matchedNonSeparator = true;
            end = i + 1;
        }
    }
    return path.slice(start, end);
}
function stripTrailingSeparators(segment, isSep) {
    if (segment.length <= 1) {
        return segment;
    }
    let end = segment.length;
    for(let i = segment.length - 1; i > 0; i--){
        if (isSep(segment.charCodeAt(i))) {
            end = i;
        } else {
            break;
        }
    }
    return segment.slice(0, end);
}
function stripSuffix(name, suffix) {
    if (suffix.length >= name.length) {
        return name;
    }
    const lenDiff = name.length - suffix.length;
    for(let i = suffix.length - 1; i >= 0; --i){
        if (name.charCodeAt(lenDiff + i) !== suffix.charCodeAt(i)) {
            return name;
        }
    }
    return name.slice(0, -suffix.length);
}
const sep = "\\";
const delimiter = ";";
function resolve(...pathSegments) {
    let resolvedDevice = "";
    let resolvedTail = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1; i--){
        let path;
        const { Deno: Deno1 } = globalThis;
        if (i >= 0) {
            path = pathSegments[i];
        } else if (!resolvedDevice) {
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a drive-letter-less path without a CWD.");
            }
            path = Deno1.cwd();
        } else {
            if (typeof Deno1?.env?.get !== "function" || typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
            if (path === undefined || path.slice(0, 3).toLowerCase() !== `${resolvedDevice.toLowerCase()}\\`) {
                path = `${resolvedDevice}\\`;
            }
        }
        assertPath(path);
        const len = path.length;
        if (len === 0) continue;
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator(code)) {
                isAbsolute = true;
                if (isPathSeparator(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        const firstPart = path.slice(last, j);
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                device = `\\\\${firstPart}\\${path.slice(last)}`;
                                rootEnd = j;
                            } else if (j !== last) {
                                device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                                rootEnd = j;
                            }
                        }
                    }
                } else {
                    rootEnd = 1;
                }
            } else if (isWindowsDeviceRoot(code)) {
                if (path.charCodeAt(1) === 58) {
                    device = path.slice(0, 2);
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator(path.charCodeAt(2))) {
                            isAbsolute = true;
                            rootEnd = 3;
                        }
                    }
                }
            }
        } else if (isPathSeparator(code)) {
            rootEnd = 1;
            isAbsolute = true;
        }
        if (device.length > 0 && resolvedDevice.length > 0 && device.toLowerCase() !== resolvedDevice.toLowerCase()) {
            continue;
        }
        if (resolvedDevice.length === 0 && device.length > 0) {
            resolvedDevice = device;
        }
        if (!resolvedAbsolute) {
            resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
            resolvedAbsolute = isAbsolute;
        }
        if (resolvedAbsolute && resolvedDevice.length > 0) break;
    }
    resolvedTail = normalizeString(resolvedTail, !resolvedAbsolute, "\\", isPathSeparator);
    return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail || ".";
}
function normalize(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = 0;
    let device;
    let isAbsolute = false;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            isAbsolute = true;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    const firstPart = path.slice(last, j);
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return `\\\\${firstPart}\\${path.slice(last)}\\`;
                        } else if (j !== last) {
                            device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                            rootEnd = j;
                        }
                    }
                }
            } else {
                rootEnd = 1;
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                device = path.slice(0, 2);
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) {
                        isAbsolute = true;
                        rootEnd = 3;
                    }
                }
            }
        }
    } else if (isPathSeparator(code)) {
        return "\\";
    }
    let tail;
    if (rootEnd < len) {
        tail = normalizeString(path.slice(rootEnd), !isAbsolute, "\\", isPathSeparator);
    } else {
        tail = "";
    }
    if (tail.length === 0 && !isAbsolute) tail = ".";
    if (tail.length > 0 && isPathSeparator(path.charCodeAt(len - 1))) {
        tail += "\\";
    }
    if (device === undefined) {
        if (isAbsolute) {
            if (tail.length > 0) return `\\${tail}`;
            else return "\\";
        } else if (tail.length > 0) {
            return tail;
        } else {
            return "";
        }
    } else if (isAbsolute) {
        if (tail.length > 0) return `${device}\\${tail}`;
        else return `${device}\\`;
    } else if (tail.length > 0) {
        return device + tail;
    } else {
        return device;
    }
}
function isAbsolute(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return false;
    const code = path.charCodeAt(0);
    if (isPathSeparator(code)) {
        return true;
    } else if (isWindowsDeviceRoot(code)) {
        if (len > 2 && path.charCodeAt(1) === 58) {
            if (isPathSeparator(path.charCodeAt(2))) return true;
        }
    }
    return false;
}
function join(...paths) {
    const pathsCount = paths.length;
    if (pathsCount === 0) return ".";
    let joined;
    let firstPart = null;
    for(let i = 0; i < pathsCount; ++i){
        const path = paths[i];
        assertPath(path);
        if (path.length > 0) {
            if (joined === undefined) joined = firstPart = path;
            else joined += `\\${path}`;
        }
    }
    if (joined === undefined) return ".";
    let needsReplace = true;
    let slashCount = 0;
    assert(firstPart != null);
    if (isPathSeparator(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
            if (isPathSeparator(firstPart.charCodeAt(1))) {
                ++slashCount;
                if (firstLen > 2) {
                    if (isPathSeparator(firstPart.charCodeAt(2))) ++slashCount;
                    else {
                        needsReplace = false;
                    }
                }
            }
        }
    }
    if (needsReplace) {
        for(; slashCount < joined.length; ++slashCount){
            if (!isPathSeparator(joined.charCodeAt(slashCount))) break;
        }
        if (slashCount >= 2) joined = `\\${joined.slice(slashCount)}`;
    }
    return normalize(joined);
}
function relative(from, to) {
    assertPath(from);
    assertPath(to);
    if (from === to) return "";
    const fromOrig = resolve(from);
    const toOrig = resolve(to);
    if (fromOrig === toOrig) return "";
    from = fromOrig.toLowerCase();
    to = toOrig.toLowerCase();
    if (from === to) return "";
    let fromStart = 0;
    let fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (from.charCodeAt(fromStart) !== 92) break;
    }
    for(; fromEnd - 1 > fromStart; --fromEnd){
        if (from.charCodeAt(fromEnd - 1) !== 92) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 0;
    let toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (to.charCodeAt(toStart) !== 92) break;
    }
    for(; toEnd - 1 > toStart; --toEnd){
        if (to.charCodeAt(toEnd - 1) !== 92) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (to.charCodeAt(toStart + i) === 92) {
                    return toOrig.slice(toStart + i + 1);
                } else if (i === 2) {
                    return toOrig.slice(toStart + i);
                }
            }
            if (fromLen > length) {
                if (from.charCodeAt(fromStart + i) === 92) {
                    lastCommonSep = i;
                } else if (i === 2) {
                    lastCommonSep = 3;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (fromCode === 92) lastCommonSep = i;
    }
    if (i !== length && lastCommonSep === -1) {
        return toOrig;
    }
    let out = "";
    if (lastCommonSep === -1) lastCommonSep = 0;
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || from.charCodeAt(i) === 92) {
            if (out.length === 0) out += "..";
            else out += "\\..";
        }
    }
    if (out.length > 0) {
        return out + toOrig.slice(toStart + lastCommonSep, toEnd);
    } else {
        toStart += lastCommonSep;
        if (toOrig.charCodeAt(toStart) === 92) ++toStart;
        return toOrig.slice(toStart, toEnd);
    }
}
function toNamespacedPath(path) {
    if (typeof path !== "string") return path;
    if (path.length === 0) return "";
    const resolvedPath = resolve(path);
    if (resolvedPath.length >= 3) {
        if (resolvedPath.charCodeAt(0) === 92) {
            if (resolvedPath.charCodeAt(1) === 92) {
                const code = resolvedPath.charCodeAt(2);
                if (code !== 63 && code !== 46) {
                    return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
                }
            }
        } else if (isWindowsDeviceRoot(resolvedPath.charCodeAt(0))) {
            if (resolvedPath.charCodeAt(1) === 58 && resolvedPath.charCodeAt(2) === 92) {
                return `\\\\?\\${resolvedPath}`;
            }
        }
    }
    return path;
}
function dirname(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = -1;
    let end = -1;
    let matchedSlash = true;
    let offset = 0;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            rootEnd = offset = 1;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return path;
                        }
                        if (j !== last) {
                            rootEnd = offset = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = offset = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) rootEnd = offset = 3;
                }
            }
        }
    } else if (isPathSeparator(code)) {
        return path;
    }
    for(let i = len - 1; i >= offset; --i){
        if (isPathSeparator(path.charCodeAt(i))) {
            if (!matchedSlash) {
                end = i;
                break;
            }
        } else {
            matchedSlash = false;
        }
    }
    if (end === -1) {
        if (rootEnd === -1) return ".";
        else end = rootEnd;
    }
    return stripTrailingSeparators(path.slice(0, end), isPosixPathSeparator);
}
function basename(path, suffix = "") {
    assertPath(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
    let start = 0;
    if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (isWindowsDeviceRoot(drive)) {
            if (path.charCodeAt(1) === 58) start = 2;
        }
    }
    const lastSegment = lastPathSegment(path, isPathSeparator, start);
    const strippedSegment = stripTrailingSeparators(lastSegment, isPathSeparator);
    return suffix ? stripSuffix(strippedSegment, suffix) : strippedSegment;
}
function extname(path) {
    assertPath(path);
    let start = 0;
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    if (path.length >= 2 && path.charCodeAt(1) === 58 && isWindowsDeviceRoot(path.charCodeAt(0))) {
        start = startPart = 2;
    }
    for(let i = path.length - 1; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format("\\", pathObject);
}
function parse(path) {
    assertPath(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    const len = path.length;
    if (len === 0) return ret;
    let rootEnd = 0;
    let code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            rootEnd = 1;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            rootEnd = j;
                        } else if (j !== last) {
                            rootEnd = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) {
                        if (len === 3) {
                            ret.root = ret.dir = path;
                            ret.base = "\\";
                            return ret;
                        }
                        rootEnd = 3;
                    }
                } else {
                    ret.root = ret.dir = path;
                    return ret;
                }
            }
        }
    } else if (isPathSeparator(code)) {
        ret.root = ret.dir = path;
        ret.base = "\\";
        return ret;
    }
    if (rootEnd > 0) ret.root = path.slice(0, rootEnd);
    let startDot = -1;
    let startPart = rootEnd;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= rootEnd; --i){
        code = path.charCodeAt(i);
        if (isPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            ret.base = ret.name = path.slice(startPart, end);
        }
    } else {
        ret.name = path.slice(startPart, startDot);
        ret.base = path.slice(startPart, end);
        ret.ext = path.slice(startDot, end);
    }
    ret.base = ret.base || "\\";
    if (startPart > 0 && startPart !== rootEnd) {
        ret.dir = path.slice(0, startPart - 1);
    } else ret.dir = ret.root;
    return ret;
}
function fromFileUrl(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    let path = decodeURIComponent(url.pathname.replace(/\//g, "\\").replace(/%(?![0-9A-Fa-f]{2})/g, "%25")).replace(/^\\*([A-Za-z]:)(\\|$)/, "$1\\");
    if (url.hostname != "") {
        path = `\\\\${url.hostname}${path}`;
    }
    return path;
}
function toFileUrl(path) {
    if (!isAbsolute(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const [, hostname, pathname] = path.match(/^(?:[/\\]{2}([^/\\]+)(?=[/\\](?:[^/\\]|$)))?(.*)/);
    const url = new URL("file:///");
    url.pathname = encodeWhitespace(pathname.replace(/%/g, "%25"));
    if (hostname != null && hostname != "localhost") {
        url.hostname = hostname;
        if (!url.hostname) {
            throw new TypeError("Invalid hostname.");
        }
    }
    return url;
}
const mod = {
    sep: sep,
    delimiter: delimiter,
    resolve: resolve,
    normalize: normalize,
    isAbsolute: isAbsolute,
    join: join,
    relative: relative,
    toNamespacedPath: toNamespacedPath,
    dirname: dirname,
    basename: basename,
    extname: extname,
    format: format,
    parse: parse,
    fromFileUrl: fromFileUrl,
    toFileUrl: toFileUrl
};
const sep1 = "/";
const delimiter1 = ":";
function resolve1(...pathSegments) {
    let resolvedPath = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1 && !resolvedAbsolute; i--){
        let path;
        if (i >= 0) path = pathSegments[i];
        else {
            const { Deno: Deno1 } = globalThis;
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
        }
        assertPath(path);
        if (path.length === 0) {
            continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute = isPosixPathSeparator(path.charCodeAt(0));
    }
    resolvedPath = normalizeString(resolvedPath, !resolvedAbsolute, "/", isPosixPathSeparator);
    if (resolvedAbsolute) {
        if (resolvedPath.length > 0) return `/${resolvedPath}`;
        else return "/";
    } else if (resolvedPath.length > 0) return resolvedPath;
    else return ".";
}
function normalize1(path) {
    assertPath(path);
    if (path.length === 0) return ".";
    const isAbsolute = isPosixPathSeparator(path.charCodeAt(0));
    const trailingSeparator = isPosixPathSeparator(path.charCodeAt(path.length - 1));
    path = normalizeString(path, !isAbsolute, "/", isPosixPathSeparator);
    if (path.length === 0 && !isAbsolute) path = ".";
    if (path.length > 0 && trailingSeparator) path += "/";
    if (isAbsolute) return `/${path}`;
    return path;
}
function isAbsolute1(path) {
    assertPath(path);
    return path.length > 0 && isPosixPathSeparator(path.charCodeAt(0));
}
function join1(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    for(let i = 0, len = paths.length; i < len; ++i){
        const path = paths[i];
        assertPath(path);
        if (path.length > 0) {
            if (!joined) joined = path;
            else joined += `/${path}`;
        }
    }
    if (!joined) return ".";
    return normalize1(joined);
}
function relative1(from, to) {
    assertPath(from);
    assertPath(to);
    if (from === to) return "";
    from = resolve1(from);
    to = resolve1(to);
    if (from === to) return "";
    let fromStart = 1;
    const fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (!isPosixPathSeparator(from.charCodeAt(fromStart))) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 1;
    const toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (!isPosixPathSeparator(to.charCodeAt(toStart))) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (isPosixPathSeparator(to.charCodeAt(toStart + i))) {
                    return to.slice(toStart + i + 1);
                } else if (i === 0) {
                    return to.slice(toStart + i);
                }
            } else if (fromLen > length) {
                if (isPosixPathSeparator(from.charCodeAt(fromStart + i))) {
                    lastCommonSep = i;
                } else if (i === 0) {
                    lastCommonSep = 0;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (isPosixPathSeparator(fromCode)) lastCommonSep = i;
    }
    let out = "";
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || isPosixPathSeparator(from.charCodeAt(i))) {
            if (out.length === 0) out += "..";
            else out += "/..";
        }
    }
    if (out.length > 0) return out + to.slice(toStart + lastCommonSep);
    else {
        toStart += lastCommonSep;
        if (isPosixPathSeparator(to.charCodeAt(toStart))) ++toStart;
        return to.slice(toStart);
    }
}
function toNamespacedPath1(path) {
    return path;
}
function dirname1(path) {
    if (path.length === 0) return ".";
    let end = -1;
    let matchedNonSeparator = false;
    for(let i = path.length - 1; i >= 1; --i){
        if (isPosixPathSeparator(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                end = i;
                break;
            }
        } else {
            matchedNonSeparator = true;
        }
    }
    if (end === -1) {
        return isPosixPathSeparator(path.charCodeAt(0)) ? "/" : ".";
    }
    return stripTrailingSeparators(path.slice(0, end), isPosixPathSeparator);
}
function basename1(path, suffix = "") {
    assertPath(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
    const lastSegment = lastPathSegment(path, isPosixPathSeparator);
    const strippedSegment = stripTrailingSeparators(lastSegment, isPosixPathSeparator);
    return suffix ? stripSuffix(strippedSegment, suffix) : strippedSegment;
}
function extname1(path) {
    assertPath(path);
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    for(let i = path.length - 1; i >= 0; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format1(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format("/", pathObject);
}
function parse1(path) {
    assertPath(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    if (path.length === 0) return ret;
    const isAbsolute = isPosixPathSeparator(path.charCodeAt(0));
    let start;
    if (isAbsolute) {
        ret.root = "/";
        start = 1;
    } else {
        start = 0;
    }
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            if (startPart === 0 && isAbsolute) {
                ret.base = ret.name = path.slice(1, end);
            } else {
                ret.base = ret.name = path.slice(startPart, end);
            }
        }
        ret.base = ret.base || "/";
    } else {
        if (startPart === 0 && isAbsolute) {
            ret.name = path.slice(1, startDot);
            ret.base = path.slice(1, end);
        } else {
            ret.name = path.slice(startPart, startDot);
            ret.base = path.slice(startPart, end);
        }
        ret.ext = path.slice(startDot, end);
    }
    if (startPart > 0) {
        ret.dir = stripTrailingSeparators(path.slice(0, startPart - 1), isPosixPathSeparator);
    } else if (isAbsolute) ret.dir = "/";
    return ret;
}
function fromFileUrl1(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    return decodeURIComponent(url.pathname.replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
}
function toFileUrl1(path) {
    if (!isAbsolute1(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const url = new URL("file:///");
    url.pathname = encodeWhitespace(path.replace(/%/g, "%25").replace(/\\/g, "%5C"));
    return url;
}
const mod1 = {
    sep: sep1,
    delimiter: delimiter1,
    resolve: resolve1,
    normalize: normalize1,
    isAbsolute: isAbsolute1,
    join: join1,
    relative: relative1,
    toNamespacedPath: toNamespacedPath1,
    dirname: dirname1,
    basename: basename1,
    extname: extname1,
    format: format1,
    parse: parse1,
    fromFileUrl: fromFileUrl1,
    toFileUrl: toFileUrl1
};
const path = isWindows ? mod : mod1;
const { join: join2, normalize: normalize2 } = path;
const path1 = isWindows ? mod : mod1;
const { basename: basename2, delimiter: delimiter2, dirname: dirname2, extname: extname2, format: format2, fromFileUrl: fromFileUrl2, isAbsolute: isAbsolute2, join: join3, normalize: normalize3, parse: parse2, relative: relative2, resolve: resolve2, sep: sep2, toFileUrl: toFileUrl2, toNamespacedPath: toNamespacedPath2 } = path1;
function lexer(str) {
    const tokens = [];
    let i = 0;
    while(i < str.length){
        const __char = str[i];
        if (__char === "*" || __char === "+" || __char === "?") {
            tokens.push({
                type: "MODIFIER",
                index: i,
                value: str[i++]
            });
            continue;
        }
        if (__char === "\\") {
            tokens.push({
                type: "ESCAPED_CHAR",
                index: i++,
                value: str[i++]
            });
            continue;
        }
        if (__char === "{") {
            tokens.push({
                type: "OPEN",
                index: i,
                value: str[i++]
            });
            continue;
        }
        if (__char === "}") {
            tokens.push({
                type: "CLOSE",
                index: i,
                value: str[i++]
            });
            continue;
        }
        if (__char === ":") {
            let name = "";
            let j = i + 1;
            while(j < str.length){
                const code = str.charCodeAt(j);
                if (code >= 48 && code <= 57 || code >= 65 && code <= 90 || code >= 97 && code <= 122 || code === 95) {
                    name += str[j++];
                    continue;
                }
                break;
            }
            if (!name) throw new TypeError(`Missing parameter name at ${i}`);
            tokens.push({
                type: "NAME",
                index: i,
                value: name
            });
            i = j;
            continue;
        }
        if (__char === "(") {
            let count = 1;
            let pattern = "";
            let j = i + 1;
            if (str[j] === "?") {
                throw new TypeError(`Pattern cannot start with "?" at ${j}`);
            }
            while(j < str.length){
                if (str[j] === "\\") {
                    pattern += str[j++] + str[j++];
                    continue;
                }
                if (str[j] === ")") {
                    count--;
                    if (count === 0) {
                        j++;
                        break;
                    }
                } else if (str[j] === "(") {
                    count++;
                    if (str[j + 1] !== "?") {
                        throw new TypeError(`Capturing groups are not allowed at ${j}`);
                    }
                }
                pattern += str[j++];
            }
            if (count) throw new TypeError(`Unbalanced pattern at ${i}`);
            if (!pattern) throw new TypeError(`Missing pattern at ${i}`);
            tokens.push({
                type: "PATTERN",
                index: i,
                value: pattern
            });
            i = j;
            continue;
        }
        tokens.push({
            type: "CHAR",
            index: i,
            value: str[i++]
        });
    }
    tokens.push({
        type: "END",
        index: i,
        value: ""
    });
    return tokens;
}
function parse3(str, options = {}) {
    const tokens = lexer(str);
    const { prefixes = "./" } = options;
    const defaultPattern = `[^${escapeString(options.delimiter || "/#?")}]+?`;
    const result = [];
    let key = 0;
    let i = 0;
    let path = "";
    const tryConsume = (type)=>{
        if (i < tokens.length && tokens[i].type === type) return tokens[i++].value;
    };
    const mustConsume = (type)=>{
        const value = tryConsume(type);
        if (value !== undefined) return value;
        const { type: nextType, index } = tokens[i];
        throw new TypeError(`Unexpected ${nextType} at ${index}, expected ${type}`);
    };
    const consumeText = ()=>{
        let result = "";
        let value;
        while(value = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")){
            result += value;
        }
        return result;
    };
    while(i < tokens.length){
        const __char = tryConsume("CHAR");
        const name = tryConsume("NAME");
        const pattern = tryConsume("PATTERN");
        if (name || pattern) {
            let prefix = __char || "";
            if (prefixes.indexOf(prefix) === -1) {
                path += prefix;
                prefix = "";
            }
            if (path) {
                result.push(path);
                path = "";
            }
            result.push({
                name: name || key++,
                prefix,
                suffix: "",
                pattern: pattern || defaultPattern,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        const value = __char || tryConsume("ESCAPED_CHAR");
        if (value) {
            path += value;
            continue;
        }
        if (path) {
            result.push(path);
            path = "";
        }
        const open = tryConsume("OPEN");
        if (open) {
            const prefix = consumeText();
            const name = tryConsume("NAME") || "";
            const pattern = tryConsume("PATTERN") || "";
            const suffix = consumeText();
            mustConsume("CLOSE");
            result.push({
                name: name || (pattern ? key++ : ""),
                pattern: name && !pattern ? defaultPattern : pattern,
                prefix,
                suffix,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        mustConsume("END");
    }
    return result;
}
function compile(str, options) {
    return tokensToFunction(parse3(str, options), options);
}
function tokensToFunction(tokens, options = {}) {
    const reFlags = flags(options);
    const { encode = (x)=>x, validate = true } = options;
    const matches = tokens.map((token)=>{
        if (typeof token === "object") {
            return new RegExp(`^(?:${token.pattern})$`, reFlags);
        }
    });
    return (data)=>{
        let path = "";
        for(let i = 0; i < tokens.length; i++){
            const token = tokens[i];
            if (typeof token === "string") {
                path += token;
                continue;
            }
            const value = data ? data[token.name] : undefined;
            const optional = token.modifier === "?" || token.modifier === "*";
            const repeat = token.modifier === "*" || token.modifier === "+";
            if (Array.isArray(value)) {
                if (!repeat) {
                    throw new TypeError(`Expected "${token.name}" to not repeat, but got an array`);
                }
                if (value.length === 0) {
                    if (optional) continue;
                    throw new TypeError(`Expected "${token.name}" to not be empty`);
                }
                for(let j = 0; j < value.length; j++){
                    const segment = encode(value[j], token);
                    if (validate && !matches[i].test(segment)) {
                        throw new TypeError(`Expected all "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                    }
                    path += token.prefix + segment + token.suffix;
                }
                continue;
            }
            if (typeof value === "string" || typeof value === "number") {
                const segment = encode(String(value), token);
                if (validate && !matches[i].test(segment)) {
                    throw new TypeError(`Expected "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                }
                path += token.prefix + segment + token.suffix;
                continue;
            }
            if (optional) continue;
            const typeOfMessage = repeat ? "an array" : "a string";
            throw new TypeError(`Expected "${token.name}" to be ${typeOfMessage}`);
        }
        return path;
    };
}
function escapeString(str) {
    return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
function flags(options) {
    return options && options.sensitive ? "" : "i";
}
function regexpToRegexp(path, keys) {
    if (!keys) return path;
    const groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
    let index = 0;
    let execResult = groupsRegex.exec(path.source);
    while(execResult){
        keys.push({
            name: execResult[1] || index++,
            prefix: "",
            suffix: "",
            modifier: "",
            pattern: ""
        });
        execResult = groupsRegex.exec(path.source);
    }
    return path;
}
function arrayToRegexp(paths, keys, options) {
    const parts = paths.map((path)=>pathToRegexp(path, keys, options).source);
    return new RegExp(`(?:${parts.join("|")})`, flags(options));
}
function stringToRegexp(path, keys, options) {
    return tokensToRegexp(parse3(path, options), keys, options);
}
function tokensToRegexp(tokens, keys, options = {}) {
    const { strict = false, start = true, end = true, encode = (x)=>x, delimiter = "/#?", endsWith = "" } = options;
    const endsWithRe = `[${escapeString(endsWith)}]|$`;
    const delimiterRe = `[${escapeString(delimiter)}]`;
    let route = start ? "^" : "";
    for (const token of tokens){
        if (typeof token === "string") {
            route += escapeString(encode(token));
        } else {
            const prefix = escapeString(encode(token.prefix));
            const suffix = escapeString(encode(token.suffix));
            if (token.pattern) {
                if (keys) keys.push(token);
                if (prefix || suffix) {
                    if (token.modifier === "+" || token.modifier === "*") {
                        const mod = token.modifier === "*" ? "?" : "";
                        route += `(?:${prefix}((?:${token.pattern})(?:${suffix}${prefix}(?:${token.pattern}))*)${suffix})${mod}`;
                    } else {
                        route += `(?:${prefix}(${token.pattern})${suffix})${token.modifier}`;
                    }
                } else {
                    if (token.modifier === "+" || token.modifier === "*") {
                        route += `((?:${token.pattern})${token.modifier})`;
                    } else {
                        route += `(${token.pattern})${token.modifier}`;
                    }
                }
            } else {
                route += `(?:${prefix}${suffix})${token.modifier}`;
            }
        }
    }
    if (end) {
        if (!strict) route += `${delimiterRe}?`;
        route += !options.endsWith ? "$" : `(?=${endsWithRe})`;
    } else {
        const endToken = tokens[tokens.length - 1];
        const isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === undefined;
        if (!strict) {
            route += `(?:${delimiterRe}(?=${endsWithRe}))?`;
        }
        if (!isEndDelimited) {
            route += `(?=${delimiterRe}|${endsWithRe})`;
        }
    }
    return new RegExp(route, flags(options));
}
function pathToRegexp(path, keys, options) {
    if (path instanceof RegExp) return regexpToRegexp(path, keys);
    if (Array.isArray(path)) return arrayToRegexp(path, keys, options);
    return stringToRegexp(path, keys, options);
}
const SUBTYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.-]{0,126}$/;
const TYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126}$/;
const TYPE_REGEXP = /^ *([A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126})\/([A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}) *$/;
class MediaType {
    type;
    subtype;
    suffix;
    constructor(type, subtype, suffix){
        this.type = type;
        this.subtype = subtype;
        this.suffix = suffix;
    }
}
function format3(obj) {
    const { subtype, suffix, type } = obj;
    if (!TYPE_NAME_REGEXP.test(type)) {
        throw new TypeError("Invalid type.");
    }
    if (!SUBTYPE_NAME_REGEXP.test(subtype)) {
        throw new TypeError("Invalid subtype.");
    }
    let str = `${type}/${subtype}`;
    if (suffix) {
        if (!TYPE_NAME_REGEXP.test(suffix)) {
            throw new TypeError("Invalid suffix.");
        }
        str += `+${suffix}`;
    }
    return str;
}
function parse4(str) {
    const match = TYPE_REGEXP.exec(str.toLowerCase());
    if (!match) {
        throw new TypeError("Invalid media type.");
    }
    let [, type, subtype] = match;
    let suffix;
    const idx = subtype.lastIndexOf("+");
    if (idx !== -1) {
        suffix = subtype.substr(idx + 1);
        subtype = subtype.substr(0, idx);
    }
    return new MediaType(type, subtype, suffix);
}
function mimeMatch(expected, actual) {
    if (expected === undefined) {
        return false;
    }
    const actualParts = actual.split("/");
    const expectedParts = expected.split("/");
    if (actualParts.length !== 2 || expectedParts.length !== 2) {
        return false;
    }
    const [actualType, actualSubtype] = actualParts;
    const [expectedType, expectedSubtype] = expectedParts;
    if (expectedType !== "*" && expectedType !== actualType) {
        return false;
    }
    if (expectedSubtype.substr(0, 2) === "*+") {
        return expectedSubtype.length <= actualSubtype.length + 1 && expectedSubtype.substr(1) === actualSubtype.substr(1 - expectedSubtype.length);
    }
    if (expectedSubtype !== "*" && expectedSubtype !== actualSubtype) {
        return false;
    }
    return true;
}
function normalize4(type) {
    if (type === "urlencoded") {
        return "application/x-www-form-urlencoded";
    } else if (type === "multipart") {
        return "multipart/*";
    } else if (type[0] === "+") {
        return `*/*${type}`;
    }
    return type.includes("/") ? type : typeByExtension(type);
}
function normalizeType(value) {
    try {
        const val = value.split(";");
        const type = parse4(val[0]);
        return format3(type);
    } catch  {
        return;
    }
}
function isMediaType(value, types) {
    const val = normalizeType(value);
    if (!val) {
        return false;
    }
    if (!types.length) {
        return val;
    }
    for (const type of types){
        if (mimeMatch(normalize4(type), val)) {
            return type[0] === "+" || type.includes("*") ? val : type;
        }
    }
    return false;
}
const ENCODE_CHARS_REGEXP = /(?:[^\x21\x25\x26-\x3B\x3D\x3F-\x5B\x5D\x5F\x61-\x7A\x7E]|%(?:[^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|$))+/g;
const HTAB = "\t".charCodeAt(0);
const SPACE = " ".charCodeAt(0);
const CR = "\r".charCodeAt(0);
const LF = "\n".charCodeAt(0);
const UNMATCHED_SURROGATE_PAIR_REGEXP = /(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF]([^\uDC00-\uDFFF]|$)/g;
const UNMATCHED_SURROGATE_PAIR_REPLACE = "$1\uFFFD$2";
const BODY_TYPES = [
    "string",
    "number",
    "bigint",
    "boolean",
    "symbol"
];
function assert1(cond, msg = "Assertion failed") {
    if (!cond) {
        throw new Error(msg);
    }
}
function decodeComponent(text) {
    try {
        return decodeURIComponent(text);
    } catch  {
        return text;
    }
}
function encodeUrl(url) {
    return String(url).replace(UNMATCHED_SURROGATE_PAIR_REGEXP, UNMATCHED_SURROGATE_PAIR_REPLACE).replace(ENCODE_CHARS_REGEXP, encodeURI);
}
function bufferToHex(buffer) {
    const arr = Array.from(new Uint8Array(buffer));
    return arr.map((b)=>b.toString(16).padStart(2, "0")).join("");
}
async function getRandomFilename(prefix = "", extension = "") {
    const buffer = await crypto.subtle.digest("SHA-1", crypto.getRandomValues(new Uint8Array(256)));
    return `${prefix}${bufferToHex(buffer)}${extension ? `.${extension}` : ""}`;
}
async function getBoundary() {
    const buffer = await crypto.subtle.digest("SHA-1", crypto.getRandomValues(new Uint8Array(256)));
    return `oak_${bufferToHex(buffer)}`;
}
function isAsyncIterable(value) {
    return typeof value === "object" && value !== null && Symbol.asyncIterator in value && typeof value[Symbol.asyncIterator] === "function";
}
function isReader(value) {
    return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function";
}
function isCloser(value) {
    return typeof value === "object" && value != null && "close" in value && typeof value["close"] === "function";
}
function isConn(value) {
    return typeof value === "object" && value != null && "rid" in value && typeof value.rid === "number" && "localAddr" in value && "remoteAddr" in value;
}
function isListenTlsOptions(value) {
    return typeof value === "object" && value !== null && ("cert" in value || "certFile" in value) && ("key" in value || "keyFile" in value) && "port" in value;
}
function readableStreamFromAsyncIterable(source) {
    return new ReadableStream({
        async start (controller) {
            for await (const chunk of source){
                if (BODY_TYPES.includes(typeof chunk)) {
                    controller.enqueue(encoder3.encode(String(chunk)));
                } else if (chunk instanceof Uint8Array) {
                    controller.enqueue(chunk);
                } else if (ArrayBuffer.isView(chunk)) {
                    controller.enqueue(new Uint8Array(chunk.buffer));
                } else if (chunk instanceof ArrayBuffer) {
                    controller.enqueue(new Uint8Array(chunk));
                } else {
                    try {
                        controller.enqueue(encoder3.encode(JSON.stringify(chunk)));
                    } catch  {}
                }
            }
            controller.close();
        }
    });
}
function readableStreamFromReader(reader, options = {}) {
    const { autoClose = true, chunkSize = 16_640, strategy } = options;
    return new ReadableStream({
        async pull (controller) {
            const chunk = new Uint8Array(chunkSize);
            try {
                const read = await reader.read(chunk);
                if (read === null) {
                    if (isCloser(reader) && autoClose) {
                        reader.close();
                    }
                    controller.close();
                    return;
                }
                controller.enqueue(chunk.subarray(0, read));
            } catch (e) {
                controller.error(e);
                if (isCloser(reader)) {
                    reader.close();
                }
            }
        },
        cancel () {
            if (isCloser(reader) && autoClose) {
                reader.close();
            }
        }
    }, strategy);
}
function isRedirectStatus(value) {
    return [
        Status.MultipleChoices,
        Status.MovedPermanently,
        Status.Found,
        Status.SeeOther,
        Status.UseProxy,
        Status.TemporaryRedirect,
        Status.PermanentRedirect
    ].includes(value);
}
function isHtml(value) {
    return /^\s*<(?:!DOCTYPE|html|body)/i.test(value);
}
function skipLWSPChar(u8) {
    const result = new Uint8Array(u8.length);
    let j = 0;
    for(let i = 0; i < u8.length; i++){
        if (u8[i] === SPACE || u8[i] === HTAB) continue;
        result[j++] = u8[i];
    }
    return result.slice(0, j);
}
function stripEol(value) {
    if (value[value.byteLength - 1] == LF) {
        let drop = 1;
        if (value.byteLength > 1 && value[value.byteLength - 2] === CR) {
            drop = 2;
        }
        return value.subarray(0, value.byteLength - drop);
    }
    return value;
}
const UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
function resolvePath(rootPath, relativePath) {
    let path = relativePath;
    let root = rootPath;
    if (relativePath === undefined) {
        path = rootPath;
        root = ".";
    }
    if (path == null) {
        throw new TypeError("Argument relativePath is required.");
    }
    if (path.includes("\0")) {
        throw createHttpError(400, "Malicious Path");
    }
    if (isAbsolute2(path)) {
        throw createHttpError(400, "Malicious Path");
    }
    if (UP_PATH_REGEXP.test(normalize3("." + sep2 + path))) {
        throw createHttpError(403);
    }
    return normalize3(join3(root, path));
}
class Uint8ArrayTransformStream extends TransformStream {
    constructor(){
        const init = {
            async transform (chunk, controller) {
                chunk = await chunk;
                switch(typeof chunk){
                    case "object":
                        if (chunk === null) {
                            controller.terminate();
                        } else if (ArrayBuffer.isView(chunk)) {
                            controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
                        } else if (Array.isArray(chunk) && chunk.every((value)=>typeof value === "number")) {
                            controller.enqueue(new Uint8Array(chunk));
                        } else if (typeof chunk.valueOf === "function" && chunk.valueOf() !== chunk) {
                            this.transform(chunk.valueOf(), controller);
                        } else if ("toJSON" in chunk) {
                            this.transform(JSON.stringify(chunk), controller);
                        }
                        break;
                    case "symbol":
                        controller.error(new TypeError("Cannot transform a symbol to a Uint8Array"));
                        break;
                    case "undefined":
                        controller.error(new TypeError("Cannot transform undefined to a Uint8Array"));
                        break;
                    default:
                        controller.enqueue(this.encoder.encode(String(chunk)));
                }
            },
            encoder: new TextEncoder()
        };
        super(init);
    }
}
const encoder3 = new TextEncoder();
const MIN_BUF_SIZE = 16;
const CR1 = "\r".charCodeAt(0);
const LF1 = "\n".charCodeAt(0);
class BufferFullError extends Error {
    partial;
    name;
    constructor(partial){
        super("Buffer full");
        this.partial = partial;
        this.name = "BufferFullError";
    }
}
class BufReader {
    #buffer;
    #reader;
    #posRead = 0;
    #posWrite = 0;
    #eof = false;
    async #fill() {
        if (this.#posRead > 0) {
            this.#buffer.copyWithin(0, this.#posRead, this.#posWrite);
            this.#posWrite -= this.#posRead;
            this.#posRead = 0;
        }
        if (this.#posWrite >= this.#buffer.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i = 100; i > 0; i--){
            const rr = await this.#reader.read(this.#buffer.subarray(this.#posWrite));
            if (rr === null) {
                this.#eof = true;
                return;
            }
            assert1(rr >= 0, "negative read");
            this.#posWrite += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    }
    #reset(buffer, reader) {
        this.#buffer = buffer;
        this.#reader = reader;
        this.#eof = false;
    }
    constructor(rd, size = 4096){
        if (size < 16) {
            size = MIN_BUF_SIZE;
        }
        this.#reset(new Uint8Array(size), rd);
    }
    buffered() {
        return this.#posWrite - this.#posRead;
    }
    async readLine(strip = true) {
        let line;
        try {
            line = await this.readSlice(LF1);
        } catch (err) {
            assert1(err instanceof Error);
            let { partial } = err;
            assert1(partial instanceof Uint8Array, "Caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError)) {
                throw err;
            }
            if (!this.#eof && partial.byteLength > 0 && partial[partial.byteLength - 1] === CR1) {
                assert1(this.#posRead > 0, "Tried to rewind past start of buffer");
                this.#posRead--;
                partial = partial.subarray(0, partial.byteLength - 1);
            }
            return {
                bytes: partial,
                eol: this.#eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                bytes: line,
                eol: true
            };
        }
        if (strip) {
            line = stripEol(line);
        }
        return {
            bytes: line,
            eol: true
        };
    }
    async readSlice(delim) {
        let s = 0;
        let slice;
        while(true){
            let i = this.#buffer.subarray(this.#posRead + s, this.#posWrite).indexOf(delim);
            if (i >= 0) {
                i += s;
                slice = this.#buffer.subarray(this.#posRead, this.#posRead + i + 1);
                this.#posRead += i + 1;
                break;
            }
            if (this.#eof) {
                if (this.#posRead === this.#posWrite) {
                    return null;
                }
                slice = this.#buffer.subarray(this.#posRead, this.#posWrite);
                this.#posRead = this.#posWrite;
                break;
            }
            if (this.buffered() >= this.#buffer.byteLength) {
                this.#posRead = this.#posWrite;
                const oldbuf = this.#buffer;
                const newbuf = this.#buffer.slice(0);
                this.#buffer = newbuf;
                throw new BufferFullError(oldbuf);
            }
            s = this.#posWrite - this.#posRead;
            try {
                await this.#fill();
            } catch (err) {
                const e = err instanceof Error ? err : new Error("[non-object thrown]");
                e.partial = slice;
                throw err;
            }
        }
        return slice;
    }
}
const COLON = ":".charCodeAt(0);
const HTAB1 = "\t".charCodeAt(0);
const SPACE1 = " ".charCodeAt(0);
const decoder = new TextDecoder();
function toParamRegExp(attributePattern, flags) {
    return new RegExp(`(?:^|;)\\s*${attributePattern}\\s*=\\s*` + `(` + `[^";\\s][^;\\s]*` + `|` + `"(?:[^"\\\\]|\\\\"?)+"?` + `)`, flags);
}
async function readHeaders(body) {
    const headers = {};
    let readResult = await body.readLine();
    while(readResult){
        const { bytes } = readResult;
        if (!bytes.length) {
            return headers;
        }
        let i = bytes.indexOf(COLON);
        if (i === -1) {
            throw new errors.BadRequest(`Malformed header: ${decoder.decode(bytes)}`);
        }
        const key = decoder.decode(bytes.subarray(0, i)).trim().toLowerCase();
        if (key === "") {
            throw new errors.BadRequest("Invalid header key.");
        }
        i++;
        while(i < bytes.byteLength && (bytes[i] === SPACE1 || bytes[i] === HTAB1)){
            i++;
        }
        const value = decoder.decode(bytes.subarray(i)).trim();
        headers[key] = value;
        readResult = await body.readLine();
    }
    throw new errors.BadRequest("Unexpected end of body reached.");
}
function unquote(value) {
    if (value.startsWith(`"`)) {
        const parts = value.slice(1).split(`\\"`);
        for(let i = 0; i < parts.length; ++i){
            const quoteIndex = parts[i].indexOf(`"`);
            if (quoteIndex !== -1) {
                parts[i] = parts[i].slice(0, quoteIndex);
                parts.length = i + 1;
            }
            parts[i] = parts[i].replace(/\\(.)/g, "$1");
        }
        value = parts.join(`"`);
    }
    return value;
}
let needsEncodingFixup = false;
function fixupEncoding(value) {
    if (needsEncodingFixup && /[\x80-\xff]/.test(value)) {
        value = textDecode("utf-8", value);
        if (needsEncodingFixup) {
            value = textDecode("iso-8859-1", value);
        }
    }
    return value;
}
const FILENAME_STAR_REGEX = toParamRegExp("filename\\*", "i");
const FILENAME_START_ITER_REGEX = toParamRegExp("filename\\*((?!0\\d)\\d+)(\\*?)", "ig");
const FILENAME_REGEX = toParamRegExp("filename", "i");
function rfc2047decode(value) {
    if (!value.startsWith("=?") || /[\x00-\x19\x80-\xff]/.test(value)) {
        return value;
    }
    return value.replace(/=\?([\w-]*)\?([QqBb])\?((?:[^?]|\?(?!=))*)\?=/g, (_, charset, encoding, text)=>{
        if (encoding === "q" || encoding === "Q") {
            text = text.replace(/_/g, " ");
            text = text.replace(/=([0-9a-fA-F]{2})/g, (_, hex)=>String.fromCharCode(parseInt(hex, 16)));
            return textDecode(charset, text);
        }
        try {
            text = atob(text);
        } catch  {}
        return textDecode(charset, text);
    });
}
function rfc2231getParam(header) {
    const matches = [];
    let match;
    while(match = FILENAME_START_ITER_REGEX.exec(header)){
        const [, ns, quote, part] = match;
        const n = parseInt(ns, 10);
        if (n in matches) {
            if (n === 0) {
                break;
            }
            continue;
        }
        matches[n] = [
            quote,
            part
        ];
    }
    const parts = [];
    for(let n = 0; n < matches.length; ++n){
        if (!(n in matches)) {
            break;
        }
        let [quote, part] = matches[n];
        part = unquote(part);
        if (quote) {
            part = unescape(part);
            if (n === 0) {
                part = rfc5987decode(part);
            }
        }
        parts.push(part);
    }
    return parts.join("");
}
function rfc5987decode(value) {
    const encodingEnd = value.indexOf(`'`);
    if (encodingEnd === -1) {
        return value;
    }
    const encoding = value.slice(0, encodingEnd);
    const langValue = value.slice(encodingEnd + 1);
    return textDecode(encoding, langValue.replace(/^[^']*'/, ""));
}
function textDecode(encoding, value) {
    if (encoding) {
        try {
            const decoder = new TextDecoder(encoding, {
                fatal: true
            });
            const bytes = Array.from(value, (c)=>c.charCodeAt(0));
            if (bytes.every((code)=>code <= 0xFF)) {
                value = decoder.decode(new Uint8Array(bytes));
                needsEncodingFixup = false;
            }
        } catch  {}
    }
    return value;
}
function getFilename(header) {
    needsEncodingFixup = true;
    let matches = FILENAME_STAR_REGEX.exec(header);
    if (matches) {
        const [, filename] = matches;
        return fixupEncoding(rfc2047decode(rfc5987decode(unescape(unquote(filename)))));
    }
    const filename = rfc2231getParam(header);
    if (filename) {
        return fixupEncoding(rfc2047decode(filename));
    }
    matches = FILENAME_REGEX.exec(header);
    if (matches) {
        const [, filename] = matches;
        return fixupEncoding(rfc2047decode(unquote(filename)));
    }
    return "";
}
const decoder1 = new TextDecoder();
const encoder4 = new TextEncoder();
const BOUNDARY_PARAM_REGEX = toParamRegExp("boundary", "i");
const NAME_PARAM_REGEX = toParamRegExp("name", "i");
function append(a, b) {
    const ab = new Uint8Array(a.length + b.length);
    ab.set(a, 0);
    ab.set(b, a.length);
    return ab;
}
function isEqual(a, b) {
    return equals(skipLWSPChar(a), b);
}
async function readToStartOrEnd(body, start, end) {
    let lineResult;
    while(lineResult = await body.readLine()){
        if (isEqual(lineResult.bytes, start)) {
            return true;
        }
        if (isEqual(lineResult.bytes, end)) {
            return false;
        }
    }
    throw new errors.BadRequest("Unable to find multi-part boundary.");
}
async function* parts({ body, customContentTypes = {}, final: __final, part, maxFileSize, maxSize, outPath, prefix }) {
    async function getFile(contentType) {
        const ext = customContentTypes[contentType.toLowerCase()] ?? extension(contentType);
        if (!ext) {
            throw new errors.BadRequest(`The form contained content type "${contentType}" which is not supported by the server.`);
        }
        if (!outPath) {
            outPath = await Deno.makeTempDir();
        }
        const filename = `${outPath}/${await getRandomFilename(prefix, ext)}`;
        const file = await Deno.open(filename, {
            write: true,
            createNew: true
        });
        return [
            filename,
            file
        ];
    }
    while(true){
        const headers = await readHeaders(body);
        const contentType = headers["content-type"];
        const contentDisposition = headers["content-disposition"];
        if (!contentDisposition) {
            throw new errors.BadRequest("Form data part missing content-disposition header");
        }
        if (!contentDisposition.match(/^form-data;/i)) {
            throw new errors.BadRequest(`Unexpected content-disposition header: "${contentDisposition}"`);
        }
        const matches = NAME_PARAM_REGEX.exec(contentDisposition);
        if (!matches) {
            throw new errors.BadRequest(`Unable to determine name of form body part`);
        }
        let [, name] = matches;
        name = unquote(name);
        if (contentType) {
            const originalName = getFilename(contentDisposition);
            let byteLength = 0;
            let file;
            let filename;
            let buf;
            if (maxSize) {
                buf = new Uint8Array();
            } else {
                const result = await getFile(contentType);
                filename = result[0];
                file = result[1];
            }
            while(true){
                const readResult = await body.readLine(false);
                if (!readResult) {
                    throw new errors.BadRequest("Unexpected EOF reached");
                }
                const { bytes } = readResult;
                const strippedBytes = stripEol(bytes);
                if (isEqual(strippedBytes, part) || isEqual(strippedBytes, __final)) {
                    if (file) {
                        const bytesDiff = bytes.length - strippedBytes.length;
                        if (bytesDiff) {
                            const originalBytesSize = await file.seek(-bytesDiff, Deno.SeekMode.Current);
                            await file.truncate(originalBytesSize);
                        }
                        file.close();
                    }
                    yield [
                        name,
                        {
                            content: buf,
                            contentType,
                            name,
                            filename,
                            originalName
                        }
                    ];
                    if (isEqual(strippedBytes, __final)) {
                        return;
                    }
                    break;
                }
                byteLength += bytes.byteLength;
                if (byteLength > maxFileSize) {
                    if (file) {
                        file.close();
                    }
                    throw new errors.RequestEntityTooLarge(`File size exceeds limit of ${maxFileSize} bytes.`);
                }
                if (buf) {
                    if (byteLength > maxSize) {
                        const result = await getFile(contentType);
                        filename = result[0];
                        file = result[1];
                        await writeAll(file, buf);
                        buf = undefined;
                    } else {
                        buf = append(buf, bytes);
                    }
                }
                if (file) {
                    await writeAll(file, bytes);
                }
            }
        } else {
            const lines = [];
            while(true){
                const readResult = await body.readLine();
                if (!readResult) {
                    throw new errors.BadRequest("Unexpected EOF reached");
                }
                const { bytes } = readResult;
                if (isEqual(bytes, part) || isEqual(bytes, __final)) {
                    yield [
                        name,
                        lines.join("\n")
                    ];
                    if (isEqual(bytes, __final)) {
                        return;
                    }
                    break;
                }
                lines.push(decoder1.decode(bytes));
            }
        }
    }
}
class FormDataReader {
    #body;
    #boundaryFinal;
    #boundaryPart;
    #reading = false;
    constructor(contentType, body){
        const matches = contentType.match(BOUNDARY_PARAM_REGEX);
        if (!matches) {
            throw new errors.BadRequest(`Content type "${contentType}" does not contain a valid boundary.`);
        }
        let [, boundary] = matches;
        boundary = unquote(boundary);
        this.#boundaryPart = encoder4.encode(`--${boundary}`);
        this.#boundaryFinal = encoder4.encode(`--${boundary}--`);
        this.#body = body;
    }
    async read(options = {}) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath, maxFileSize = 10_485_760, maxSize = 0, bufferSize = 1_048_576, customContentTypes } = options;
        const body = new BufReader(this.#body, bufferSize);
        const result = {
            fields: {}
        };
        if (!await readToStartOrEnd(body, this.#boundaryPart, this.#boundaryFinal)) {
            return result;
        }
        try {
            for await (const part of parts({
                body,
                customContentTypes,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                const [key, value] = part;
                if (typeof value === "string") {
                    result.fields[key] = value;
                } else {
                    if (!result.files) {
                        result.files = [];
                    }
                    result.files.push(value);
                }
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
        return result;
    }
    async *stream(options = {}) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath, customContentTypes, maxFileSize = 10_485_760, maxSize = 0, bufferSize = 32000 } = options;
        const body = new BufReader(this.#body, bufferSize);
        if (!await readToStartOrEnd(body, this.#boundaryPart, this.#boundaryFinal)) {
            return;
        }
        try {
            for await (const part of parts({
                body,
                customContentTypes,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                yield part;
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({})}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({}, newOptions)}`;
    }
}
const defaultBodyContentTypes = {
    json: [
        "json",
        "application/*+json",
        "application/csp-report"
    ],
    form: [
        "urlencoded"
    ],
    formData: [
        "multipart"
    ],
    text: [
        "text"
    ]
};
function resolveType(contentType, contentTypes) {
    const contentTypesJson = [
        ...defaultBodyContentTypes.json,
        ...contentTypes.json ?? []
    ];
    const contentTypesForm = [
        ...defaultBodyContentTypes.form,
        ...contentTypes.form ?? []
    ];
    const contentTypesFormData = [
        ...defaultBodyContentTypes.formData,
        ...contentTypes.formData ?? []
    ];
    const contentTypesText = [
        ...defaultBodyContentTypes.text,
        ...contentTypes.text ?? []
    ];
    if (contentTypes.bytes && isMediaType(contentType, contentTypes.bytes)) {
        return "bytes";
    } else if (isMediaType(contentType, contentTypesJson)) {
        return "json";
    } else if (isMediaType(contentType, contentTypesForm)) {
        return "form";
    } else if (isMediaType(contentType, contentTypesFormData)) {
        return "form-data";
    } else if (isMediaType(contentType, contentTypesText)) {
        return "text";
    }
    return "bytes";
}
const decoder2 = new TextDecoder();
class RequestBody {
    #body;
    #formDataReader;
    #headers;
    #jsonBodyReviver;
    #stream;
    #readAllBody;
    #readBody;
    #type;
    #exceedsLimit(limit) {
        if (!limit || limit === Infinity) {
            return false;
        }
        if (!this.#body) {
            return false;
        }
        const contentLength = this.#headers.get("content-length") ?? "0";
        const parsed = parseInt(contentLength, 10);
        if (isNaN(parsed)) {
            return true;
        }
        return parsed > limit;
    }
    #parse(type, limit) {
        switch(type){
            case "form":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
                }
                return async ()=>new URLSearchParams(decoder2.decode(await this.#valuePromise()).replace(/\+/g, " "));
            case "form-data":
                this.#type = "form-data";
                return ()=>{
                    const contentType = this.#headers.get("content-type");
                    assert1(contentType);
                    const readableStream = this.#body ?? new ReadableStream();
                    return this.#formDataReader ?? (this.#formDataReader = new FormDataReader(contentType, readerFromStreamReader(readableStream.getReader())));
                };
            case "json":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
                }
                return async ()=>{
                    const value = await this.#valuePromise();
                    return value.length ? JSON.parse(decoder2.decode(await this.#valuePromise()), this.#jsonBodyReviver) : null;
                };
            case "bytes":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
                }
                return ()=>this.#valuePromise();
            case "text":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
                }
                return async ()=>decoder2.decode(await this.#valuePromise());
            default:
                throw new TypeError(`Invalid body type: "${type}"`);
        }
    }
    #validateGetArgs(type, contentTypes) {
        if (type === "reader" && this.#type && this.#type !== "reader") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a reader.`);
        }
        if (type === "stream" && this.#type && this.#type !== "stream") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (type === "form-data" && this.#type && this.#type !== "form-data") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (this.#type === "reader" && type !== "reader") {
            throw new TypeError("Body already consumed as a reader and can only be returned as a reader.");
        }
        if (this.#type === "stream" && type !== "stream") {
            throw new TypeError("Body already consumed as a stream and can only be returned as a stream.");
        }
        if (this.#type === "form-data" && type !== "form-data") {
            throw new TypeError("Body already consumed as form data and can only be returned as form data.");
        }
        if (type && Object.keys(contentTypes).length) {
            throw new TypeError(`"type" and "contentTypes" cannot be specified at the same time`);
        }
    }
    #valuePromise() {
        return this.#readAllBody ?? (this.#readAllBody = this.#readBody());
    }
    constructor({ body, readBody }, headers, jsonBodyReviver){
        this.#body = body;
        this.#headers = headers;
        this.#jsonBodyReviver = jsonBodyReviver;
        this.#readBody = readBody;
    }
    get({ limit = 10_485_760, type, contentTypes = {} } = {}) {
        this.#validateGetArgs(type, contentTypes);
        if (type === "reader") {
            if (!this.#body) {
                this.#type = "undefined";
                throw new TypeError(`Body is undefined and cannot be returned as "reader".`);
            }
            this.#type = "reader";
            return {
                type,
                value: readerFromStreamReader(this.#body.getReader())
            };
        }
        if (type === "stream") {
            if (!this.#body) {
                this.#type = "undefined";
                throw new TypeError(`Body is undefined and cannot be returned as "stream".`);
            }
            this.#type = "stream";
            const streams = (this.#stream ?? this.#body).tee();
            this.#stream = streams[1];
            return {
                type,
                value: streams[0]
            };
        }
        if (!this.has()) {
            this.#type = "undefined";
        } else if (!this.#type) {
            const encoding = this.#headers.get("content-encoding") ?? "identity";
            if (encoding !== "identity") {
                throw new errors.UnsupportedMediaType(`Unsupported content-encoding: ${encoding}`);
            }
        }
        if (this.#type === "undefined" && (!type || type === "undefined")) {
            return {
                type: "undefined",
                value: undefined
            };
        }
        if (!type) {
            const contentType = this.#headers.get("content-type");
            assert1(contentType, "The Content-Type header is missing from the request");
            type = resolveType(contentType, contentTypes);
        }
        assert1(type);
        const body = Object.create(null);
        Object.defineProperties(body, {
            type: {
                value: type,
                configurable: true,
                enumerable: true
            },
            value: {
                get: this.#parse(type, limit),
                configurable: true,
                enumerable: true
            }
        });
        return body;
    }
    has() {
        return this.#body != null;
    }
}
class Request {
    #body;
    #proxy;
    #secure;
    #serverRequest;
    #url;
    #getRemoteAddr() {
        return this.#serverRequest.remoteAddr ?? "";
    }
    get hasBody() {
        return this.#body.has();
    }
    get headers() {
        return this.#serverRequest.headers;
    }
    get ip() {
        return (this.#proxy ? this.ips[0] : this.#getRemoteAddr()) ?? "";
    }
    get ips() {
        return this.#proxy ? (this.#serverRequest.headers.get("x-forwarded-for") ?? this.#getRemoteAddr()).split(/\s*,\s*/) : [];
    }
    get method() {
        return this.#serverRequest.method;
    }
    get secure() {
        return this.#secure;
    }
    get originalRequest() {
        return this.#serverRequest;
    }
    get url() {
        if (!this.#url) {
            const serverRequest = this.#serverRequest;
            if (!this.#proxy) {
                try {
                    if (serverRequest.rawUrl) {
                        this.#url = new URL(serverRequest.rawUrl);
                        return this.#url;
                    }
                } catch  {}
            }
            let proto;
            let host;
            if (this.#proxy) {
                proto = serverRequest.headers.get("x-forwarded-proto")?.split(/\s*,\s*/, 1)[0] ?? "http";
                host = serverRequest.headers.get("x-forwarded-host") ?? serverRequest.headers.get("host") ?? "";
            } else {
                proto = this.#secure ? "https" : "http";
                host = serverRequest.headers.get("host") ?? "";
            }
            try {
                this.#url = new URL(`${proto}://${host}${serverRequest.url}`);
            } catch  {
                throw new TypeError(`The server request URL of "${proto}://${host}${serverRequest.url}" is invalid.`);
            }
        }
        return this.#url;
    }
    constructor(serverRequest, { proxy = false, secure = false, jsonBodyReviver } = {}){
        this.#proxy = proxy;
        this.#secure = secure;
        this.#serverRequest = serverRequest;
        this.#body = new RequestBody(serverRequest.getBody(), serverRequest.headers, jsonBodyReviver);
    }
    accepts(...types) {
        if (!this.#serverRequest.headers.has("Accept")) {
            return types.length ? types[0] : [
                "*/*"
            ];
        }
        if (types.length) {
            return accepts(this.#serverRequest, ...types);
        }
        return accepts(this.#serverRequest);
    }
    acceptsEncodings(...encodings) {
        if (!this.#serverRequest.headers.has("Accept-Encoding")) {
            return encodings.length ? encodings[0] : [
                "*"
            ];
        }
        if (encodings.length) {
            return acceptsEncodings(this.#serverRequest, ...encodings);
        }
        return acceptsEncodings(this.#serverRequest);
    }
    acceptsLanguages(...langs) {
        if (!this.#serverRequest.headers.get("Accept-Language")) {
            return langs.length ? langs[0] : [
                "*"
            ];
        }
        if (langs.length) {
            return acceptsLanguages(this.#serverRequest, ...langs);
        }
        return acceptsLanguages(this.#serverRequest);
    }
    body(options = {}) {
        return this.#body.get(options);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { hasBody, headers, ip, ips, method, secure, url } = this;
        return `${this.constructor.name} ${inspect({
            hasBody,
            headers,
            ip,
            ips,
            method,
            secure,
            url: url.toString()
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { hasBody, headers, ip, ips, method, secure, url } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            hasBody,
            headers,
            ip,
            ips,
            method,
            secure,
            url
        }, newOptions)}`;
    }
}
const DomResponse = globalThis.Response ?? class MockResponse {
};
const maybeUpgradeWebSocket = "upgradeWebSocket" in Deno ? Deno.upgradeWebSocket.bind(Deno) : undefined;
class NativeRequest {
    #conn;
    #reject;
    #request;
    #requestPromise;
    #resolve;
    #resolved = false;
    #upgradeWebSocket;
    constructor(requestEvent, options = {}){
        const { conn } = options;
        this.#conn = conn;
        this.#upgradeWebSocket = "upgradeWebSocket" in options ? options["upgradeWebSocket"] : maybeUpgradeWebSocket;
        this.#request = requestEvent.request;
        const p = new Promise((resolve, reject)=>{
            this.#resolve = resolve;
            this.#reject = reject;
        });
        this.#requestPromise = requestEvent.respondWith(p);
    }
    get body() {
        return this.#request.body;
    }
    get donePromise() {
        return this.#requestPromise;
    }
    get headers() {
        return this.#request.headers;
    }
    get method() {
        return this.#request.method;
    }
    get remoteAddr() {
        return (this.#conn?.remoteAddr)?.hostname;
    }
    get request() {
        return this.#request;
    }
    get url() {
        try {
            const url = new URL(this.#request.url);
            return this.#request.url.replace(url.origin, "");
        } catch  {}
        return this.#request.url;
    }
    get rawUrl() {
        return this.#request.url;
    }
    error(reason) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#reject(reason);
        this.#resolved = true;
    }
    getBody() {
        return {
            body: this.#request.body,
            readBody: async ()=>{
                const ab = await this.#request.arrayBuffer();
                return new Uint8Array(ab);
            }
        };
    }
    respond(response) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#resolve(response);
        this.#resolved = true;
        return this.#requestPromise;
    }
    upgrade(options) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        if (!this.#upgradeWebSocket) {
            throw new TypeError("Upgrading web sockets not supported.");
        }
        const { response, socket } = this.#upgradeWebSocket(this.#request, options);
        this.#resolve(response);
        this.#resolved = true;
        return socket;
    }
}
const REDIRECT_BACK = Symbol("redirect backwards");
async function convertBodyToBodyInit(body, type, jsonBodyReplacer) {
    let result;
    if (BODY_TYPES.includes(typeof body)) {
        result = String(body);
        type = type ?? (isHtml(result) ? "html" : "text/plain");
    } else if (isReader(body)) {
        result = readableStreamFromReader(body);
    } else if (ArrayBuffer.isView(body) || body instanceof ArrayBuffer || body instanceof Blob || body instanceof URLSearchParams) {
        result = body;
    } else if (body instanceof ReadableStream) {
        result = body.pipeThrough(new Uint8ArrayTransformStream());
    } else if (body instanceof FormData) {
        result = body;
        type = "multipart/form-data";
    } else if (isAsyncIterable(body)) {
        result = readableStreamFromAsyncIterable(body);
    } else if (body && typeof body === "object") {
        result = JSON.stringify(body, jsonBodyReplacer);
        type = type ?? "json";
    } else if (typeof body === "function") {
        const result = body.call(null);
        return convertBodyToBodyInit(await result, type, jsonBodyReplacer);
    } else if (body) {
        throw new TypeError("Response body was set but could not be converted.");
    }
    return [
        result,
        type
    ];
}
class Response1 {
    #body;
    #bodySet = false;
    #domResponse;
    #headers = new Headers();
    #jsonBodyReplacer;
    #request;
    #resources = [];
    #status;
    #type;
    #writable = true;
    async #getBodyInit() {
        const [body, type] = await convertBodyToBodyInit(this.body, this.type, this.#jsonBodyReplacer);
        this.type = type;
        return body;
    }
    #setContentType() {
        if (this.type) {
            const contentTypeString = contentType(this.type);
            if (contentTypeString && !this.headers.has("Content-Type")) {
                this.headers.append("Content-Type", contentTypeString);
            }
        }
    }
    get body() {
        return this.#body;
    }
    set body(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#bodySet = true;
        this.#body = value;
    }
    get headers() {
        return this.#headers;
    }
    set headers(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#headers = value;
    }
    get status() {
        if (this.#status) {
            return this.#status;
        }
        return this.body != null ? Status.OK : this.#bodySet ? Status.NoContent : Status.NotFound;
    }
    set status(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#status = value;
    }
    get type() {
        return this.#type;
    }
    set type(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#type = value;
    }
    get writable() {
        return this.#writable;
    }
    constructor(request, jsonBodyReplacer){
        this.#request = request;
        this.#jsonBodyReplacer = jsonBodyReplacer;
    }
    addResource(rid) {
        this.#resources.push(rid);
    }
    destroy(closeResources = true) {
        this.#writable = false;
        this.#body = undefined;
        this.#domResponse = undefined;
        if (closeResources) {
            for (const rid of this.#resources){
                try {
                    Deno.close(rid);
                } catch  {}
            }
        }
    }
    redirect(url, alt = "/") {
        if (url === REDIRECT_BACK) {
            url = this.#request.headers.get("Referer") ?? String(alt);
        } else if (typeof url === "object") {
            url = String(url);
        }
        this.headers.set("Location", encodeUrl(url));
        if (!this.status || !isRedirectStatus(this.status)) {
            this.status = Status.Found;
        }
        if (this.#request.accepts("html")) {
            url = encodeURI(url);
            this.type = "text/html; charset=UTF-8";
            this.body = `Redirecting to <a href="${url}">${url}</a>.`;
            return;
        }
        this.type = "text/plain; charset=UTF-8";
        this.body = `Redirecting to ${url}.`;
    }
    async toDomResponse() {
        if (this.#domResponse) {
            return this.#domResponse;
        }
        const bodyInit = await this.#getBodyInit();
        this.#setContentType();
        const { headers } = this;
        if (!(bodyInit || headers.has("Content-Type") || headers.has("Content-Length"))) {
            headers.append("Content-Length", "0");
        }
        this.#writable = false;
        const status = this.status;
        const responseInit = {
            headers,
            status,
            statusText: STATUS_TEXT[status]
        };
        return this.#domResponse = new DomResponse(bodyInit, responseInit);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { body, headers, status, type, writable } = this;
        return `${this.constructor.name} ${inspect({
            body,
            headers,
            status,
            type,
            writable
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { body, headers, status, type, writable } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            body,
            headers,
            status,
            type,
            writable
        }, newOptions)}`;
    }
}
const ETAG_RE = /(?:W\/)?"[ !#-\x7E\x80-\xFF]+"/;
async function ifRange(value, mtime, entity) {
    if (value) {
        const matches = value.match(ETAG_RE);
        if (matches) {
            const [match] = matches;
            if (await calculate(entity) === match) {
                return true;
            }
        } else {
            return new Date(value).getTime() >= mtime;
        }
    }
    return false;
}
function parseRange(value, size) {
    const ranges = [];
    const [unit, rangesStr] = value.split("=");
    if (unit !== "bytes") {
        throw createHttpError(Status.RequestedRangeNotSatisfiable);
    }
    for (const range of rangesStr.split(/\s*,\s+/)){
        const item = range.split("-");
        if (item.length !== 2) {
            throw createHttpError(Status.RequestedRangeNotSatisfiable);
        }
        const [startStr, endStr] = item;
        let start;
        let end;
        try {
            if (startStr === "") {
                start = size - parseInt(endStr, 10) - 1;
                end = size - 1;
            } else if (endStr === "") {
                start = parseInt(startStr, 10);
                end = size - 1;
            } else {
                start = parseInt(startStr, 10);
                end = parseInt(endStr, 10);
            }
        } catch  {
            throw createHttpError();
        }
        if (start < 0 || start >= size || end < 0 || end >= size || start > end) {
            throw createHttpError(Status.RequestedRangeNotSatisfiable);
        }
        ranges.push({
            start,
            end
        });
    }
    return ranges;
}
async function readRange(file, range) {
    let length = range.end - range.start + 1;
    assert1(length);
    await file.seek(range.start, Deno.SeekMode.Start);
    const result = new Uint8Array(length);
    let off = 0;
    while(length){
        const p = new Uint8Array(Math.min(length, 16_640));
        const nread = await file.read(p);
        assert1(nread !== null, "Unexpected EOF encountered when reading a range.");
        assert1(nread > 0, "Unexpected read of 0 bytes while reading a range.");
        copy(p, result, off);
        off += nread;
        length -= nread;
        assert1(length >= 0, "Unexpected length remaining.");
    }
    return result;
}
const encoder5 = new TextEncoder();
class MultiPartStream extends ReadableStream {
    #contentLength;
    #postscript;
    #preamble;
    constructor(file, type, ranges, size, boundary){
        super({
            pull: async (controller)=>{
                const range = ranges.shift();
                if (!range) {
                    controller.enqueue(this.#postscript);
                    controller.close();
                    if (!(file instanceof Uint8Array)) {
                        file.close();
                    }
                    return;
                }
                let bytes;
                if (file instanceof Uint8Array) {
                    bytes = file.subarray(range.start, range.end + 1);
                } else {
                    bytes = await readRange(file, range);
                }
                const rangeHeader = encoder5.encode(`Content-Range: ${range.start}-${range.end}/${size}\n\n`);
                controller.enqueue(concat(this.#preamble, rangeHeader, bytes));
            }
        });
        const resolvedType = contentType(type);
        if (!resolvedType) {
            throw new TypeError(`Could not resolve media type for "${type}"`);
        }
        this.#preamble = encoder5.encode(`\n--${boundary}\nContent-Type: ${resolvedType}\n`);
        this.#postscript = encoder5.encode(`\n--${boundary}--\n`);
        this.#contentLength = ranges.reduce((prev, { start, end })=>{
            return prev + this.#preamble.length + String(start).length + String(end).length + String(size).length + 20 + (end - start);
        }, this.#postscript.length);
    }
    contentLength() {
        return this.#contentLength;
    }
}
let boundary;
function isHidden(path) {
    const pathArr = path.split("/");
    for (const segment of pathArr){
        if (segment[0] === "." && segment !== "." && segment !== "..") {
            return true;
        }
        return false;
    }
}
async function exists(path) {
    try {
        return (await Deno.stat(path)).isFile;
    } catch  {
        return false;
    }
}
async function getEntity(path, mtime, stats, maxbuffer, response) {
    let body;
    let entity;
    const file = await Deno.open(path, {
        read: true
    });
    if (stats.size < maxbuffer) {
        const buffer = await readAll(file);
        file.close();
        body = entity = buffer;
    } else {
        response.addResource(file.rid);
        body = file;
        entity = {
            mtime: new Date(mtime),
            size: stats.size
        };
    }
    return [
        body,
        entity
    ];
}
async function sendRange(response, body, range, size) {
    const ranges = parseRange(range, size);
    if (ranges.length === 0) {
        throw createHttpError(Status.RequestedRangeNotSatisfiable);
    }
    response.status = Status.PartialContent;
    if (ranges.length === 1) {
        const [byteRange] = ranges;
        response.headers.set("Content-Range", `bytes ${byteRange.start}-${byteRange.end}/${size}`);
        if (body instanceof Uint8Array) {
            response.body = body.slice(byteRange.start, byteRange.end + 1);
        } else {
            await body.seek(byteRange.start, Deno.SeekMode.Start);
            response.body = new LimitedReader(body, byteRange.end - byteRange.start + 1);
        }
    } else {
        assert1(response.type);
        if (!boundary) {
            boundary = await getBoundary();
        }
        response.headers.set("content-type", `multipart/byteranges; boundary=${boundary}`);
        const multipartBody = new MultiPartStream(body, response.type, ranges, size, boundary);
        response.body = multipartBody;
    }
}
async function send({ request, response }, path, options = {
    root: ""
}) {
    const { brotli = true, contentTypes = {}, extensions, format = true, gzip = true, hidden = false, immutable = false, index, maxbuffer = 1_048_576, maxage = 0, root } = options;
    const trailingSlash = path[path.length - 1] === "/";
    path = decodeComponent(path.substr(parse2(path).root.length));
    if (index && trailingSlash) {
        path += index;
    }
    if (!hidden && isHidden(path)) {
        throw createHttpError(403);
    }
    path = resolvePath(root, path);
    let encodingExt = "";
    if (brotli && request.acceptsEncodings("br", "identity") === "br" && await exists(`${path}.br`)) {
        path = `${path}.br`;
        response.headers.set("Content-Encoding", "br");
        response.headers.delete("Content-Length");
        encodingExt = ".br";
    } else if (gzip && request.acceptsEncodings("gzip", "identity") === "gzip" && await exists(`${path}.gz`)) {
        path = `${path}.gz`;
        response.headers.set("Content-Encoding", "gzip");
        response.headers.delete("Content-Length");
        encodingExt = ".gz";
    }
    if (extensions && !/\.[^/]*$/.exec(path)) {
        for (let ext of extensions){
            if (!/^\./.exec(ext)) {
                ext = `.${ext}`;
            }
            if (await exists(`${path}${ext}`)) {
                path += ext;
                break;
            }
        }
    }
    let stats;
    try {
        stats = await Deno.stat(path);
        if (stats.isDirectory) {
            if (format && index) {
                path += `/${index}`;
                stats = await Deno.stat(path);
            } else {
                return;
            }
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            throw createHttpError(404, err.message);
        }
        if (err instanceof Error && err.message.startsWith("ENOENT:")) {
            throw createHttpError(404, err.message);
        }
        throw createHttpError(500, err instanceof Error ? err.message : "[non-error thrown]");
    }
    let mtime = null;
    if (response.headers.has("Last-Modified")) {
        mtime = new Date(response.headers.get("Last-Modified")).getTime();
    } else if (stats.mtime) {
        mtime = stats.mtime.getTime();
        mtime -= mtime % 1000;
        response.headers.set("Last-Modified", new Date(mtime).toUTCString());
    }
    if (!response.headers.has("Cache-Control")) {
        const directives = [
            `max-age=${maxage / 1000 | 0}`
        ];
        if (immutable) {
            directives.push("immutable");
        }
        response.headers.set("Cache-Control", directives.join(","));
    }
    if (!response.type) {
        response.type = encodingExt !== "" ? extname2(basename2(path, encodingExt)) : contentTypes[extname2(path)] ?? extname2(path);
    }
    let entity = null;
    let body = null;
    if (request.headers.has("If-None-Match") && mtime) {
        [body, entity] = await getEntity(path, mtime, stats, maxbuffer, response);
        const etag = await calculate(entity);
        if (etag && !await ifNoneMatch(request.headers.get("If-None-Match"), etag)) {
            response.headers.set("ETag", etag);
            response.status = 304;
            return path;
        }
    }
    if (request.headers.has("If-Modified-Since") && mtime) {
        const ifModifiedSince = new Date(request.headers.get("If-Modified-Since"));
        if (ifModifiedSince.getTime() >= mtime) {
            response.status = 304;
            return path;
        }
    }
    if (!body || !entity) {
        [body, entity] = await getEntity(path, mtime ?? 0, stats, maxbuffer, response);
    }
    if (request.headers.has("If-Range") && mtime && await ifRange(request.headers.get("If-Range"), mtime, entity) && request.headers.has("Range")) {
        await sendRange(response, body, request.headers.get("Range"), stats.size);
        return path;
    }
    if (request.headers.has("Range")) {
        await sendRange(response, body, request.headers.get("Range"), stats.size);
        return path;
    }
    response.body = body;
    if (!response.headers.has("ETag")) {
        const etag = await calculate(entity);
        if (etag) {
            response.headers.set("ETag", etag);
        }
    }
    if (!response.headers.has("Accept-Ranges")) {
        response.headers.set("Accept-Ranges", "bytes");
    }
    return path;
}
class Context {
    #socket;
    #sse;
    #wrapReviverReplacer(reviver) {
        return reviver ? (key, value)=>reviver(key, value, this) : undefined;
    }
    app;
    cookies;
    get isUpgradable() {
        const upgrade = this.request.headers.get("upgrade");
        if (!upgrade || upgrade.toLowerCase() !== "websocket") {
            return false;
        }
        const secKey = this.request.headers.get("sec-websocket-key");
        return typeof secKey === "string" && secKey != "";
    }
    respond;
    request;
    response;
    get socket() {
        return this.#socket;
    }
    state;
    constructor(app, serverRequest, state, { secure = false, jsonBodyReplacer, jsonBodyReviver } = {}){
        this.app = app;
        this.state = state;
        const { proxy } = app;
        this.request = new Request(serverRequest, {
            proxy,
            secure,
            jsonBodyReviver: this.#wrapReviverReplacer(jsonBodyReviver)
        });
        this.respond = true;
        this.response = new Response1(this.request, this.#wrapReviverReplacer(jsonBodyReplacer));
        this.cookies = new SecureCookieMap(serverRequest, {
            keys: this.app.keys,
            response: this.response,
            secure: this.request.secure
        });
    }
    assert(condition, errorStatus = 500, message, props) {
        if (condition) {
            return;
        }
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    send(options) {
        const { path = this.request.url.pathname, ...sendOptions } = options;
        return send(this, path, sendOptions);
    }
    sendEvents(options) {
        if (!this.#sse) {
            assert1(this.response.writable, "The response is not writable.");
            const sse = this.#sse = new ServerSentEventStreamTarget(options);
            this.app.addEventListener("close", ()=>sse.close());
            const [bodyInit, { headers }] = sse.asResponseInit({
                headers: this.response.headers
            });
            this.response.body = bodyInit;
            if (headers instanceof Headers) {
                this.response.headers = headers;
            }
        }
        return this.#sse;
    }
    throw(errorStatus, message, props) {
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    upgrade(options) {
        if (this.#socket) {
            return this.#socket;
        }
        if (!this.request.originalRequest.upgrade) {
            throw new TypeError("Web socket upgrades not currently supported for this type of server.");
        }
        this.#socket = this.request.originalRequest.upgrade(options);
        this.app.addEventListener("close", ()=>this.#socket?.close());
        this.respond = false;
        return this.#socket;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { app, cookies, isUpgradable, respond, request, response, socket, state } = this;
        return `${this.constructor.name} ${inspect({
            app,
            cookies,
            isUpgradable,
            respond,
            request,
            response,
            socket,
            state
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { app, cookies, isUpgradable, respond, request, response, socket, state } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            app,
            cookies,
            isUpgradable,
            respond,
            request,
            response,
            socket,
            state
        }, newOptions)}`;
    }
}
const serveHttp = "serveHttp" in Deno ? Deno.serveHttp.bind(Deno) : undefined;
class HttpServer {
    #app;
    #closed = false;
    #listener;
    #httpConnections = new Set();
    #options;
    constructor(app, options){
        if (!("serveHttp" in Deno)) {
            throw new Error("The native bindings for serving HTTP are not available.");
        }
        this.#app = app;
        this.#options = options;
    }
    get app() {
        return this.#app;
    }
    get closed() {
        return this.#closed;
    }
    close() {
        this.#closed = true;
        if (this.#listener) {
            this.#listener.close();
            this.#listener = undefined;
        }
        for (const httpConn of this.#httpConnections){
            try {
                httpConn.close();
            } catch (error) {
                if (!(error instanceof Deno.errors.BadResource)) {
                    throw error;
                }
            }
        }
        this.#httpConnections.clear();
    }
    listen() {
        return this.#listener = isListenTlsOptions(this.#options) ? Deno.listenTls(this.#options) : Deno.listen(this.#options);
    }
    #trackHttpConnection(httpConn) {
        this.#httpConnections.add(httpConn);
    }
    #untrackHttpConnection(httpConn) {
        this.#httpConnections.delete(httpConn);
    }
    [Symbol.asyncIterator]() {
        const start = (controller)=>{
            const server = this;
            async function serve(conn) {
                const httpConn = serveHttp(conn);
                server.#trackHttpConnection(httpConn);
                while(true){
                    try {
                        const requestEvent = await httpConn.nextRequest();
                        if (requestEvent === null) {
                            return;
                        }
                        const nativeRequest = new NativeRequest(requestEvent, {
                            conn
                        });
                        controller.enqueue(nativeRequest);
                        nativeRequest.donePromise.catch((error)=>{
                            server.app.dispatchEvent(new ErrorEvent("error", {
                                error
                            }));
                        });
                    } catch (error) {
                        server.app.dispatchEvent(new ErrorEvent("error", {
                            error
                        }));
                    }
                    if (server.closed) {
                        server.#untrackHttpConnection(httpConn);
                        httpConn.close();
                        controller.close();
                    }
                }
            }
            const listener = this.#listener;
            assert1(listener);
            async function accept() {
                while(true){
                    try {
                        const conn = await listener.accept();
                        serve(conn);
                    } catch (error) {
                        if (!server.closed) {
                            server.app.dispatchEvent(new ErrorEvent("error", {
                                error
                            }));
                        }
                    }
                    if (server.closed) {
                        controller.close();
                        return;
                    }
                }
            }
            accept();
        };
        const stream = new ReadableStream({
            start
        });
        return stream[Symbol.asyncIterator]();
    }
}
function isMiddlewareObject(value) {
    return value && typeof value === "object" && "handleRequest" in value;
}
function compose(middleware) {
    return function composedMiddleware(context, next) {
        let index = -1;
        async function dispatch(i) {
            if (i <= index) {
                throw new Error("next() called multiple times.");
            }
            index = i;
            let m = middleware[i];
            let fn;
            if (typeof m === "function") {
                fn = m;
            } else if (m && typeof m.handleRequest === "function") {
                fn = m.handleRequest.bind(m);
            }
            if (i === middleware.length) {
                fn = next;
            }
            if (!fn) {
                return;
            }
            await fn(context, dispatch.bind(null, i + 1));
        }
        return dispatch(0);
    };
}
const objectCloneMemo = new WeakMap();
function cloneArrayBuffer(srcBuffer, srcByteOffset, srcLength, _cloneConstructor) {
    return srcBuffer.slice(srcByteOffset, srcByteOffset + srcLength);
}
function cloneValue(value) {
    switch(typeof value){
        case "number":
        case "string":
        case "boolean":
        case "undefined":
        case "bigint":
            return value;
        case "object":
            {
                if (objectCloneMemo.has(value)) {
                    return objectCloneMemo.get(value);
                }
                if (value === null) {
                    return value;
                }
                if (value instanceof Date) {
                    return new Date(value.valueOf());
                }
                if (value instanceof RegExp) {
                    return new RegExp(value);
                }
                if (value instanceof SharedArrayBuffer) {
                    return value;
                }
                if (value instanceof ArrayBuffer) {
                    const cloned = cloneArrayBuffer(value, 0, value.byteLength, ArrayBuffer);
                    objectCloneMemo.set(value, cloned);
                    return cloned;
                }
                if (ArrayBuffer.isView(value)) {
                    const clonedBuffer = cloneValue(value.buffer);
                    let length;
                    if (value instanceof DataView) {
                        length = value.byteLength;
                    } else {
                        length = value.length;
                    }
                    return new value.constructor(clonedBuffer, value.byteOffset, length);
                }
                if (value instanceof Map) {
                    const clonedMap = new Map();
                    objectCloneMemo.set(value, clonedMap);
                    value.forEach((v, k)=>{
                        clonedMap.set(cloneValue(k), cloneValue(v));
                    });
                    return clonedMap;
                }
                if (value instanceof Set) {
                    const clonedSet = new Set([
                        ...value
                    ].map(cloneValue));
                    objectCloneMemo.set(value, clonedSet);
                    return clonedSet;
                }
                const clonedObj = {};
                objectCloneMemo.set(value, clonedObj);
                const sourceKeys = Object.getOwnPropertyNames(value);
                for (const key of sourceKeys){
                    clonedObj[key] = cloneValue(value[key]);
                }
                Reflect.setPrototypeOf(clonedObj, Reflect.getPrototypeOf(value));
                return clonedObj;
            }
        case "symbol":
        case "function":
        default:
            throw new DOMException("Uncloneable value in stream", "DataCloneError");
    }
}
const core = Deno?.core;
const structuredClone = globalThis.structuredClone;
function sc(value) {
    return structuredClone ? structuredClone(value) : core ? core.deserialize(core.serialize(value)) : cloneValue(value);
}
function cloneState(state) {
    const clone = {};
    for (const [key, value] of Object.entries(state)){
        try {
            const clonedValue = sc(value);
            clone[key] = clonedValue;
        } catch  {}
    }
    return clone;
}
const ADDR_REGEXP = /^\[?([^\]]*)\]?:([0-9]{1,5})$/;
class ApplicationCloseEvent extends Event {
    constructor(eventInitDict){
        super("close", eventInitDict);
    }
}
class ApplicationErrorEvent extends ErrorEvent {
    context;
    constructor(eventInitDict){
        super("error", eventInitDict);
        this.context = eventInitDict.context;
    }
}
function logErrorListener({ error, context }) {
    if (error instanceof Error) {
        console.error(`[uncaught application error]: ${error.name} - ${error.message}`);
    } else {
        console.error(`[uncaught application error]\n`, error);
    }
    if (context) {
        let url;
        try {
            url = context.request.url.toString();
        } catch  {
            url = "[malformed url]";
        }
        console.error(`\nrequest:`, {
            url,
            method: context.request.method,
            hasBody: context.request.hasBody
        });
        console.error(`response:`, {
            status: context.response.status,
            type: context.response.type,
            hasBody: !!context.response.body,
            writable: context.response.writable
        });
    }
    if (error instanceof Error && error.stack) {
        console.error(`\n${error.stack.split("\n").slice(1).join("\n")}`);
    }
}
class ApplicationListenEvent extends Event {
    hostname;
    listener;
    port;
    secure;
    serverType;
    constructor(eventInitDict){
        super("listen", eventInitDict);
        this.hostname = eventInitDict.hostname;
        this.listener = eventInitDict.listener;
        this.port = eventInitDict.port;
        this.secure = eventInitDict.secure;
        this.serverType = eventInitDict.serverType;
    }
}
class Application extends EventTarget {
    #composedMiddleware;
    #contextOptions;
    #contextState;
    #keys;
    #middleware = [];
    #serverConstructor;
    get keys() {
        return this.#keys;
    }
    set keys(keys) {
        if (!keys) {
            this.#keys = undefined;
            return;
        } else if (Array.isArray(keys)) {
            this.#keys = new KeyStack(keys);
        } else {
            this.#keys = keys;
        }
    }
    proxy;
    state;
    constructor(options = {}){
        super();
        const { state, keys, proxy, serverConstructor = HttpServer, contextState = "clone", logErrors = true, ...contextOptions } = options;
        this.proxy = proxy ?? false;
        this.keys = keys;
        this.state = state ?? {};
        this.#serverConstructor = serverConstructor;
        this.#contextOptions = contextOptions;
        this.#contextState = contextState;
        if (logErrors) {
            this.addEventListener("error", logErrorListener);
        }
    }
    #getComposed() {
        if (!this.#composedMiddleware) {
            this.#composedMiddleware = compose(this.#middleware);
        }
        return this.#composedMiddleware;
    }
    #getContextState() {
        switch(this.#contextState){
            case "alias":
                return this.state;
            case "clone":
                return cloneState(this.state);
            case "empty":
                return {};
            case "prototype":
                return Object.create(this.state);
        }
    }
    #handleError(context, error) {
        if (!(error instanceof Error)) {
            error = new Error(`non-error thrown: ${JSON.stringify(error)}`);
        }
        const { message } = error;
        this.dispatchEvent(new ApplicationErrorEvent({
            context,
            message,
            error
        }));
        if (!context.response.writable) {
            return;
        }
        for (const key of [
            ...context.response.headers.keys()
        ]){
            context.response.headers.delete(key);
        }
        if (error.headers && error.headers instanceof Headers) {
            for (const [key, value] of error.headers){
                context.response.headers.set(key, value);
            }
        }
        context.response.type = "text";
        const status = context.response.status = Deno.errors && error instanceof Deno.errors.NotFound ? 404 : error.status && typeof error.status === "number" ? error.status : 500;
        context.response.body = error.expose ? error.message : STATUS_TEXT[status];
    }
    async #handleRequest(request, secure, state) {
        let context;
        try {
            context = new Context(this, request, this.#getContextState(), {
                secure,
                ...this.#contextOptions
            });
        } catch (e) {
            const error = e instanceof Error ? e : new Error(`non-error thrown: ${JSON.stringify(e)}`);
            const { message } = error;
            this.dispatchEvent(new ApplicationErrorEvent({
                message,
                error
            }));
            return;
        }
        assert1(context, "Context was not created.");
        let resolve;
        const handlingPromise = new Promise((res)=>resolve = res);
        state.handling.add(handlingPromise);
        if (!state.closing && !state.closed) {
            try {
                await this.#getComposed()(context);
            } catch (err) {
                this.#handleError(context, err);
            }
        }
        if (context.respond === false) {
            context.response.destroy();
            resolve();
            state.handling.delete(handlingPromise);
            return;
        }
        let closeResources = true;
        let response;
        try {
            closeResources = false;
            response = await context.response.toDomResponse();
        } catch (err) {
            this.#handleError(context, err);
            response = await context.response.toDomResponse();
        }
        assert1(response);
        try {
            await request.respond(response);
        } catch (err) {
            this.#handleError(context, err);
        } finally{
            context.response.destroy(closeResources);
            resolve();
            state.handling.delete(handlingPromise);
            if (state.closing) {
                await state.server.close();
                if (!state.closed) {
                    this.dispatchEvent(new ApplicationCloseEvent({}));
                }
                state.closed = true;
            }
        }
    }
    addEventListener(type, listener, options) {
        super.addEventListener(type, listener, options);
    }
    handle = async (request, secureOrConn, secure = false)=>{
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        assert1(isConn(secureOrConn) || typeof secureOrConn === "undefined");
        const contextRequest = new NativeRequest({
            request,
            respondWith () {
                return Promise.resolve(undefined);
            }
        }, {
            conn: secureOrConn
        });
        const context = new Context(this, contextRequest, this.#getContextState(), {
            secure,
            ...this.#contextOptions
        });
        try {
            await this.#getComposed()(context);
        } catch (err) {
            this.#handleError(context, err);
        }
        if (context.respond === false) {
            context.response.destroy();
            return;
        }
        try {
            const response = await context.response.toDomResponse();
            context.response.destroy(false);
            return response;
        } catch (err) {
            this.#handleError(context, err);
            throw err;
        }
    };
    async listen(options = {
        port: 0
    }) {
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        for (const middleware of this.#middleware){
            if (isMiddlewareObject(middleware) && middleware.init) {
                await middleware.init();
            }
        }
        if (typeof options === "string") {
            const match = ADDR_REGEXP.exec(options);
            if (!match) {
                throw TypeError(`Invalid address passed: "${options}"`);
            }
            const [, hostname, portStr] = match;
            options = {
                hostname,
                port: parseInt(portStr, 10)
            };
        }
        options = Object.assign({
            port: 0
        }, options);
        const server = new this.#serverConstructor(this, options);
        const { signal } = options;
        const state = {
            closed: false,
            closing: false,
            handling: new Set(),
            server
        };
        if (signal) {
            signal.addEventListener("abort", ()=>{
                if (!state.handling.size) {
                    server.close();
                    state.closed = true;
                    this.dispatchEvent(new ApplicationCloseEvent({}));
                }
                state.closing = true;
            });
        }
        const { secure = false } = options;
        const serverType = server instanceof HttpServer ? "native" : "custom";
        const listener = await server.listen();
        const { hostname, port } = listener.addr;
        this.dispatchEvent(new ApplicationListenEvent({
            hostname,
            listener,
            port,
            secure,
            serverType
        }));
        try {
            for await (const request of server){
                this.#handleRequest(request, secure, state);
            }
            await Promise.all(state.handling);
        } catch (error) {
            const message = error instanceof Error ? error.message : "Application Error";
            this.dispatchEvent(new ApplicationErrorEvent({
                message,
                error
            }));
        }
    }
    use(...middleware) {
        this.#middleware.push(...middleware);
        this.#composedMiddleware = undefined;
        return this;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { keys, proxy, state } = this;
        return `${this.constructor.name} ${inspect({
            "#middleware": this.#middleware,
            keys,
            proxy,
            state
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { keys, proxy, state } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            "#middleware": this.#middleware,
            keys,
            proxy,
            state
        }, newOptions)}`;
    }
}
function toUrl(url, params = {}, options) {
    const tokens = parse3(url);
    let replace = {};
    if (tokens.some((token)=>typeof token === "object")) {
        replace = params;
    } else {
        options = params;
    }
    const toPath = compile(url, options);
    const replaced = toPath(replace);
    if (options && options.query) {
        const url = new URL(replaced, "http://oak");
        if (typeof options.query === "string") {
            url.search = options.query;
        } else {
            url.search = String(options.query instanceof URLSearchParams ? options.query : new URLSearchParams(options.query));
        }
        return `${url.pathname}${url.search}${url.hash}`;
    }
    return replaced;
}
class Layer {
    #opts;
    #paramNames = [];
    #regexp;
    methods;
    name;
    path;
    stack;
    constructor(path, methods, middleware, { name, ...opts } = {}){
        this.#opts = opts;
        this.name = name;
        this.methods = [
            ...methods
        ];
        if (this.methods.includes("GET")) {
            this.methods.unshift("HEAD");
        }
        this.stack = Array.isArray(middleware) ? middleware.slice() : [
            middleware
        ];
        this.path = path;
        this.#regexp = pathToRegexp(path, this.#paramNames, this.#opts);
    }
    clone() {
        return new Layer(this.path, this.methods, this.stack, {
            name: this.name,
            ...this.#opts
        });
    }
    match(path) {
        return this.#regexp.test(path);
    }
    params(captures, existingParams = {}) {
        const params = existingParams;
        for(let i = 0; i < captures.length; i++){
            if (this.#paramNames[i]) {
                const c = captures[i];
                params[this.#paramNames[i].name] = c ? decodeComponent(c) : c;
            }
        }
        return params;
    }
    captures(path) {
        if (this.#opts.ignoreCaptures) {
            return [];
        }
        return path.match(this.#regexp)?.slice(1) ?? [];
    }
    url(params = {}, options) {
        const url = this.path.replace(/\(\.\*\)/g, "");
        return toUrl(url, params, options);
    }
    param(param, fn) {
        const stack = this.stack;
        const params = this.#paramNames;
        const middleware = function(ctx, next) {
            const p = ctx.params[param];
            assert1(p);
            return fn.call(this, p, ctx, next);
        };
        middleware.param = param;
        const names = params.map((p)=>p.name);
        const x = names.indexOf(param);
        if (x >= 0) {
            for(let i = 0; i < stack.length; i++){
                const fn = stack[i];
                if (!fn.param || names.indexOf(fn.param) > x) {
                    stack.splice(i, 0, middleware);
                    break;
                }
            }
        }
        return this;
    }
    setPrefix(prefix) {
        if (this.path) {
            this.path = this.path !== "/" || this.#opts.strict === true ? `${prefix}${this.path}` : prefix;
            this.#paramNames = [];
            this.#regexp = pathToRegexp(this.path, this.#paramNames, this.#opts);
        }
        return this;
    }
    toJSON() {
        return {
            methods: [
                ...this.methods
            ],
            middleware: [
                ...this.stack
            ],
            paramNames: this.#paramNames.map((key)=>key.name),
            path: this.path,
            regexp: this.#regexp,
            options: {
                ...this.#opts
            }
        };
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            methods: this.methods,
            middleware: this.stack,
            options: this.#opts,
            paramNames: this.#paramNames.map((key)=>key.name),
            path: this.path,
            regexp: this.#regexp
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            methods: this.methods,
            middleware: this.stack,
            options: this.#opts,
            paramNames: this.#paramNames.map((key)=>key.name),
            path: this.path,
            regexp: this.#regexp
        }, newOptions)}`;
    }
}
class Router {
    #opts;
    #methods;
    #params = {};
    #stack = [];
    #match(path, method) {
        const matches = {
            path: [],
            pathAndMethod: [],
            route: false
        };
        for (const route of this.#stack){
            if (route.match(path)) {
                matches.path.push(route);
                if (route.methods.length === 0 || route.methods.includes(method)) {
                    matches.pathAndMethod.push(route);
                    if (route.methods.length) {
                        matches.route = true;
                        matches.name = route.name;
                    }
                }
            }
        }
        return matches;
    }
    #register(path, middlewares, methods, options = {}) {
        if (Array.isArray(path)) {
            for (const p of path){
                this.#register(p, middlewares, methods, options);
            }
            return;
        }
        let layerMiddlewares = [];
        for (const middleware of middlewares){
            if (!middleware.router) {
                layerMiddlewares.push(middleware);
                continue;
            }
            if (layerMiddlewares.length) {
                this.#addLayer(path, layerMiddlewares, methods, options);
                layerMiddlewares = [];
            }
            const router = middleware.router.#clone();
            for (const layer of router.#stack){
                if (!options.ignorePrefix) {
                    layer.setPrefix(path);
                }
                if (this.#opts.prefix) {
                    layer.setPrefix(this.#opts.prefix);
                }
                this.#stack.push(layer);
            }
            for (const [param, mw] of Object.entries(this.#params)){
                router.param(param, mw);
            }
        }
        if (layerMiddlewares.length) {
            this.#addLayer(path, layerMiddlewares, methods, options);
        }
    }
    #addLayer(path, middlewares, methods, options = {}) {
        const { end, name, sensitive = this.#opts.sensitive, strict = this.#opts.strict, ignoreCaptures } = options;
        const route = new Layer(path, methods, middlewares, {
            end,
            name,
            sensitive,
            strict,
            ignoreCaptures
        });
        if (this.#opts.prefix) {
            route.setPrefix(this.#opts.prefix);
        }
        for (const [param, mw] of Object.entries(this.#params)){
            route.param(param, mw);
        }
        this.#stack.push(route);
    }
    #route(name) {
        for (const route of this.#stack){
            if (route.name === name) {
                return route;
            }
        }
    }
    #useVerb(nameOrPath, pathOrMiddleware, middleware, methods) {
        let name = undefined;
        let path;
        if (typeof pathOrMiddleware === "string") {
            name = nameOrPath;
            path = pathOrMiddleware;
        } else {
            path = nameOrPath;
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path, middleware, methods, {
            name
        });
    }
    #clone() {
        const router = new Router(this.#opts);
        router.#methods = router.#methods.slice();
        router.#params = {
            ...this.#params
        };
        router.#stack = this.#stack.map((layer)=>layer.clone());
        return router;
    }
    constructor(opts = {}){
        this.#opts = opts;
        this.#methods = opts.methods ?? [
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT"
        ];
    }
    add(methods, nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, typeof methods === "string" ? [
            methods
        ] : methods);
        return this;
    }
    all(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, this.#methods.filter((method)=>method !== "OPTIONS"));
        return this;
    }
    allowedMethods(options = {}) {
        const implemented = this.#methods;
        const allowedMethods = async (context, next)=>{
            const ctx = context;
            await next();
            if (!ctx.response.status || ctx.response.status === Status.NotFound) {
                assert1(ctx.matched);
                const allowed = new Set();
                for (const route of ctx.matched){
                    for (const method of route.methods){
                        allowed.add(method);
                    }
                }
                const allowedStr = [
                    ...allowed
                ].join(", ");
                if (!implemented.includes(ctx.request.method)) {
                    if (options.throw) {
                        throw options.notImplemented ? options.notImplemented() : new errors.NotImplemented();
                    } else {
                        ctx.response.status = Status.NotImplemented;
                        ctx.response.headers.set("Allow", allowedStr);
                    }
                } else if (allowed.size) {
                    if (ctx.request.method === "OPTIONS") {
                        ctx.response.status = Status.OK;
                        ctx.response.headers.set("Allow", allowedStr);
                    } else if (!allowed.has(ctx.request.method)) {
                        if (options.throw) {
                            throw options.methodNotAllowed ? options.methodNotAllowed() : new errors.MethodNotAllowed();
                        } else {
                            ctx.response.status = Status.MethodNotAllowed;
                            ctx.response.headers.set("Allow", allowedStr);
                        }
                    }
                }
            }
        };
        return allowedMethods;
    }
    delete(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "DELETE"
        ]);
        return this;
    }
    *entries() {
        for (const route of this.#stack){
            const value = route.toJSON();
            yield [
                value,
                value
            ];
        }
    }
    forEach(callback, thisArg = null) {
        for (const route of this.#stack){
            const value = route.toJSON();
            callback.call(thisArg, value, value, this);
        }
    }
    get(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "GET"
        ]);
        return this;
    }
    head(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "HEAD"
        ]);
        return this;
    }
    *keys() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    options(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "OPTIONS"
        ]);
        return this;
    }
    param(param, middleware) {
        this.#params[param] = middleware;
        for (const route of this.#stack){
            route.param(param, middleware);
        }
        return this;
    }
    patch(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PATCH"
        ]);
        return this;
    }
    post(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "POST"
        ]);
        return this;
    }
    prefix(prefix) {
        prefix = prefix.replace(/\/$/, "");
        this.#opts.prefix = prefix;
        for (const route of this.#stack){
            route.setPrefix(prefix);
        }
        return this;
    }
    put(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PUT"
        ]);
        return this;
    }
    redirect(source, destination, status = Status.Found) {
        if (source[0] !== "/") {
            const s = this.url(source);
            if (!s) {
                throw new RangeError(`Could not resolve named route: "${source}"`);
            }
            source = s;
        }
        if (typeof destination === "string") {
            if (destination[0] !== "/") {
                const d = this.url(destination);
                if (!d) {
                    try {
                        const url = new URL(destination);
                        destination = url;
                    } catch  {
                        throw new RangeError(`Could not resolve named route: "${source}"`);
                    }
                } else {
                    destination = d;
                }
            }
        }
        this.all(source, async (ctx, next)=>{
            await next();
            ctx.response.redirect(destination);
            ctx.response.status = status;
        });
        return this;
    }
    routes() {
        const dispatch = (context, next)=>{
            const ctx = context;
            let pathname;
            let method;
            try {
                const { url: { pathname: p }, method: m } = ctx.request;
                pathname = p;
                method = m;
            } catch (e) {
                return Promise.reject(e);
            }
            const path = this.#opts.routerPath ?? ctx.routerPath ?? decodeURI(pathname);
            const matches = this.#match(path, method);
            if (ctx.matched) {
                ctx.matched.push(...matches.path);
            } else {
                ctx.matched = [
                    ...matches.path
                ];
            }
            ctx.router = this;
            if (!matches.route) return next();
            ctx.routeName = matches.name;
            const { pathAndMethod: matchedRoutes } = matches;
            const chain = matchedRoutes.reduce((prev, route)=>[
                    ...prev,
                    (ctx, next)=>{
                        ctx.captures = route.captures(path);
                        ctx.params = route.params(ctx.captures, ctx.params);
                        return next();
                    },
                    ...route.stack
                ], []);
            return compose(chain)(ctx, next);
        };
        dispatch.router = this;
        return dispatch;
    }
    url(name, params, options) {
        const route = this.#route(name);
        if (route) {
            return route.url(params, options);
        }
    }
    use(pathOrMiddleware, ...middleware) {
        let path;
        if (typeof pathOrMiddleware === "string" || Array.isArray(pathOrMiddleware)) {
            path = pathOrMiddleware;
        } else {
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path ?? "(.*)", middleware, [], {
            end: false,
            ignoreCaptures: !path,
            ignorePrefix: !path
        });
        return this;
    }
    *values() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    *[Symbol.iterator]() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    static url(path, params, options) {
        return toUrl(path, params, options);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            "#params": this.#params,
            "#stack": this.#stack
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            "#params": this.#params,
            "#stack": this.#stack
        }, newOptions)}`;
    }
}
class Cors {
    props;
    constructor(props){
        this.props = props;
        this.configureHeaders = ()=>{
            const { props: { corsOptions, requestMethod, setResponseHeader, setStatus, next, end }, configureOrigin } = this;
            if (typeof requestMethod === "string" && requestMethod.toUpperCase() === "OPTIONS") {
                configureOrigin().configureCredentials().configureMethods().configureAllowedHeaders().configureMaxAge().configureExposedHeaders();
                if (corsOptions.preflightContinue) return next();
                else {
                    setStatus(corsOptions.optionsSuccessStatus);
                    setResponseHeader("Content-Length", "0");
                    return end();
                }
            } else {
                configureOrigin().configureCredentials().configureExposedHeaders();
                return next();
            }
        };
        this.configureOrigin = ()=>{
            const { props: { corsOptions, getRequestHeader, setResponseHeader }, setVaryHeader } = this;
            if (!corsOptions.origin || corsOptions.origin === "*") {
                setResponseHeader("Access-Control-Allow-Origin", "*");
            } else if (typeof corsOptions.origin === "string") {
                setResponseHeader("Access-Control-Allow-Origin", corsOptions.origin);
                setVaryHeader("Origin");
            } else {
                const requestOrigin = getRequestHeader("origin") ?? getRequestHeader("Origin");
                setResponseHeader("Access-Control-Allow-Origin", Cors.isOriginAllowed(requestOrigin, corsOptions.origin) ? requestOrigin : "false");
                setVaryHeader("Origin");
            }
            return this;
        };
        this.configureCredentials = ()=>{
            const { corsOptions, setResponseHeader } = this.props;
            if (corsOptions.credentials === true) {
                setResponseHeader("Access-Control-Allow-Credentials", "true");
            }
            return this;
        };
        this.configureMethods = ()=>{
            const { corsOptions, setResponseHeader } = this.props;
            let methods = corsOptions.methods;
            setResponseHeader("Access-Control-Allow-Methods", Array.isArray(methods) ? methods.join(",") : methods);
            return this;
        };
        this.configureAllowedHeaders = ()=>{
            const { props: { corsOptions, getRequestHeader, setResponseHeader }, setVaryHeader } = this;
            let allowedHeaders = corsOptions.allowedHeaders;
            if (!allowedHeaders) {
                allowedHeaders = getRequestHeader("access-control-request-headers") ?? getRequestHeader("Access-Control-Request-Headers") ?? undefined;
                setVaryHeader("Access-Control-request-Headers");
            }
            if (allowedHeaders?.length) {
                setResponseHeader("Access-Control-Allow-Headers", Array.isArray(allowedHeaders) ? allowedHeaders.join(",") : allowedHeaders);
            }
            return this;
        };
        this.configureMaxAge = ()=>{
            const { corsOptions, setResponseHeader } = this.props;
            const maxAge = (typeof corsOptions.maxAge === "number" || typeof corsOptions.maxAge === "string") && corsOptions.maxAge.toString();
            if (maxAge && maxAge.length) {
                setResponseHeader("Access-Control-Max-Age", maxAge);
            }
            return this;
        };
        this.configureExposedHeaders = ()=>{
            const { corsOptions, setResponseHeader } = this.props;
            let exposedHeaders = corsOptions.exposedHeaders;
            if (exposedHeaders?.length) {
                setResponseHeader("Access-Control-Expose-Headers", Array.isArray(exposedHeaders) ? exposedHeaders.join(",") : exposedHeaders);
            }
            return this;
        };
        this.setVaryHeader = (field)=>{
            const { props: { getResponseHeader, setResponseHeader }, appendVaryHeader } = this;
            let existingHeader = getResponseHeader("Vary") ?? "";
            if (existingHeader && typeof existingHeader === "string" && (existingHeader = appendVaryHeader(existingHeader, field))) {
                setResponseHeader("Vary", existingHeader);
            }
        };
        this.appendVaryHeader = (header, field)=>{
            const { parseVaryHeader } = this;
            if (header === "*") return header;
            let varyHeader = header;
            const fields = parseVaryHeader(field);
            const headers = parseVaryHeader(header.toLocaleLowerCase());
            if (fields.includes("*") || headers.includes("*")) return "*";
            fields.forEach((field)=>{
                const fld = field.toLowerCase();
                if (headers.includes(fld)) {
                    headers.push(fld);
                    varyHeader = varyHeader ? `${varyHeader}, ${field}` : field;
                }
            });
            return varyHeader;
        };
        this.parseVaryHeader = (header)=>{
            let end = 0;
            const list = [];
            let start = 0;
            for(let i = 0, len = header.length; i < len; i++){
                switch(header.charCodeAt(i)){
                    case 0x20:
                        if (start === end) start = end = i + 1;
                        break;
                    case 0x2c:
                        list.push(header.substring(start, end));
                        start = end = i + 1;
                        break;
                    default:
                        end = i + 1;
                        break;
                }
            }
            list.push(header.substring(start, end));
            return list;
        };
    }
    static produceCorsOptions = (corsOptions = {}, defaultCorsOptions = {
        origin: "*",
        methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
        preflightContinue: false,
        optionsSuccessStatus: 204
    })=>({
            ...defaultCorsOptions,
            ...corsOptions
        });
    static produceCorsOptionsDelegate = (o)=>typeof o === "function" ? o : (_request)=>o;
    static produceOriginDelegate = (corsOptions)=>{
        if (corsOptions.origin) {
            if (typeof corsOptions.origin === "function") {
                return corsOptions.origin;
            }
            return (_requestOrigin)=>corsOptions.origin;
        }
    };
    static isOriginAllowed = (requestOrigin, allowedOrigin)=>{
        if (Array.isArray(allowedOrigin)) {
            return allowedOrigin.some((ao)=>Cors.isOriginAllowed(requestOrigin, ao));
        } else if (typeof allowedOrigin === "string") {
            return requestOrigin === allowedOrigin;
        } else if (allowedOrigin instanceof RegExp && typeof requestOrigin === "string") {
            return allowedOrigin.test(requestOrigin);
        } else return !!allowedOrigin;
    };
    configureHeaders;
    configureOrigin;
    configureCredentials;
    configureMethods;
    configureAllowedHeaders;
    configureMaxAge;
    configureExposedHeaders;
    setVaryHeader;
    appendVaryHeader;
    parseVaryHeader;
}
const oakCors = (o)=>{
    const corsOptionsDelegate = Cors.produceCorsOptionsDelegate(o);
    return async ({ request, response }, next)=>{
        try {
            const options = await corsOptionsDelegate(request);
            const corsOptions = Cors.produceCorsOptions(options || {});
            const originDelegate = Cors.produceOriginDelegate(corsOptions);
            if (originDelegate) {
                const requestMethod = request.method;
                const getRequestHeader = (headerKey)=>request.headers.get(headerKey);
                const getResponseHeader = (headerKey)=>response.headers.get(headerKey);
                const setResponseHeader = (headerKey, headerValue)=>response.headers.set(headerKey, headerValue);
                const setStatus = (statusCode)=>response.status = statusCode;
                const end = ()=>{};
                const origin = await originDelegate(getRequestHeader("origin"));
                if (!origin) next();
                else {
                    corsOptions.origin = origin;
                    return new Cors({
                        corsOptions,
                        requestMethod,
                        getRequestHeader,
                        getResponseHeader,
                        setResponseHeader,
                        setStatus,
                        next,
                        end
                    }).configureHeaders();
                }
            }
        } catch (error) {
            console.error(error);
        }
        next();
    };
};
const { Deno: Deno1 } = globalThis;
const noColor = typeof Deno1?.noColor === "boolean" ? Deno1.noColor : false;
let enabled = !noColor;
function setColorEnabled(value) {
    if (Deno1?.noColor) {
        return;
    }
    enabled = value;
}
function getColorEnabled() {
    return enabled;
}
function code(open, close) {
    return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g")
    };
}
function run(str, code) {
    return enabled ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}` : str;
}
function bold(str) {
    return run(str, code([
        1
    ], 22));
}
function dim(str) {
    return run(str, code([
        2
    ], 22));
}
function italic(str) {
    return run(str, code([
        3
    ], 23));
}
function red(str) {
    return run(str, code([
        31
    ], 39));
}
function green(str) {
    return run(str, code([
        32
    ], 39));
}
function yellow(str) {
    return run(str, code([
        33
    ], 39));
}
function brightBlue(str) {
    return run(str, code([
        94
    ], 39));
}
function brightMagenta(str) {
    return run(str, code([
        95
    ], 39));
}
const ANSI_PATTERN = new RegExp([
    "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
    "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-nq-uy=><~]))"
].join("|"), "g");
function stripColor(string) {
    return string.replace(ANSI_PATTERN, "");
}
function distance(a, b) {
    if (a.length == 0) {
        return b.length;
    }
    if (b.length == 0) {
        return a.length;
    }
    const matrix = [];
    for(let i = 0; i <= b.length; i++){
        matrix[i] = [
            i
        ];
    }
    for(let j = 0; j <= a.length; j++){
        matrix[0][j] = j;
    }
    for(let i = 1; i <= b.length; i++){
        for(let j = 1; j <= a.length; j++){
            if (b.charAt(i - 1) == a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
            }
        }
    }
    return matrix[b.length][a.length];
}
function paramCaseToCamelCase(str) {
    return str.replace(/-([a-z])/g, (g)=>g[1].toUpperCase());
}
function underscoreToCamelCase(str) {
    return str.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase().replace(/_([a-z])/g, (g)=>g[1].toUpperCase());
}
function getOption(flags, name) {
    while(name[0] === "-"){
        name = name.slice(1);
    }
    for (const flag of flags){
        if (isOption(flag, name)) {
            return flag;
        }
    }
    return;
}
function didYouMeanOption(option, options) {
    const optionNames = options.map((option)=>[
            option.name,
            ...option.aliases ?? []
        ]).flat().map((option)=>getFlag(option));
    return didYouMean(" Did you mean option", getFlag(option), optionNames);
}
function didYouMeanType(type, types) {
    return didYouMean(" Did you mean type", type, types);
}
function didYouMean(message, type, types) {
    const match = closest(type, types);
    return match ? `${message} "${match}"?` : "";
}
function getFlag(name) {
    if (name.startsWith("-")) {
        return name;
    }
    if (name.length > 1) {
        return `--${name}`;
    }
    return `-${name}`;
}
function isOption(option, name) {
    return option.name === name || option.aliases && option.aliases.indexOf(name) !== -1;
}
function matchWildCardOptions(name, flags) {
    for (const option of flags){
        if (option.name.indexOf("*") === -1) {
            continue;
        }
        let matched = matchWildCardOption(name, option);
        if (matched) {
            matched = {
                ...matched,
                name
            };
            flags.push(matched);
            return matched;
        }
    }
}
function matchWildCardOption(name, option) {
    const parts = option.name.split(".");
    const parts2 = name.split(".");
    if (parts.length !== parts2.length) {
        return false;
    }
    const count = Math.max(parts.length, parts2.length);
    for(let i = 0; i < count; i++){
        if (parts[i] !== parts2[i] && parts[i] !== "*") {
            return false;
        }
    }
    return option;
}
function closest(str, arr) {
    let minDistance = Infinity;
    let minIndex = 0;
    for(let i = 0; i < arr.length; i++){
        const dist = distance(str, arr[i]);
        if (dist < minDistance) {
            minDistance = dist;
            minIndex = i;
        }
    }
    return arr[minIndex];
}
function getDefaultValue(option) {
    return typeof option.default === "function" ? option.default() : option.default;
}
class FlagsError extends Error {
    constructor(message){
        super(message);
        Object.setPrototypeOf(this, FlagsError.prototype);
    }
}
class UnknownRequiredOptionError extends FlagsError {
    constructor(option, options){
        super(`Unknown required option "${getFlag(option)}".${didYouMeanOption(option, options)}`);
        Object.setPrototypeOf(this, UnknownRequiredOptionError.prototype);
    }
}
class UnknownConflictingOptionError extends FlagsError {
    constructor(option, options){
        super(`Unknown conflicting option "${getFlag(option)}".${didYouMeanOption(option, options)}`);
        Object.setPrototypeOf(this, UnknownConflictingOptionError.prototype);
    }
}
class UnknownTypeError extends FlagsError {
    constructor(type, types){
        super(`Unknown type "${type}".${didYouMeanType(type, types)}`);
        Object.setPrototypeOf(this, UnknownTypeError.prototype);
    }
}
class ValidationError extends FlagsError {
    constructor(message){
        super(message);
        Object.setPrototypeOf(this, ValidationError.prototype);
    }
}
class DuplicateOptionError extends ValidationError {
    constructor(name){
        super(`Option "${getFlag(name).replace(/^--no-/, "--")}" can only occur once, but was found several times.`);
        Object.setPrototypeOf(this, DuplicateOptionError.prototype);
    }
}
class InvalidOptionError extends ValidationError {
    constructor(option, options){
        super(`Invalid option "${getFlag(option)}".${didYouMeanOption(option, options)}`);
        Object.setPrototypeOf(this, InvalidOptionError.prototype);
    }
}
class UnknownOptionError extends ValidationError {
    constructor(option, options){
        super(`Unknown option "${getFlag(option)}".${didYouMeanOption(option, options)}`);
        Object.setPrototypeOf(this, UnknownOptionError.prototype);
    }
}
class MissingOptionValueError extends ValidationError {
    constructor(option){
        super(`Missing value for option "${getFlag(option)}".`);
        Object.setPrototypeOf(this, MissingOptionValueError.prototype);
    }
}
class InvalidOptionValueError extends ValidationError {
    constructor(option, expected, value){
        super(`Option "${getFlag(option)}" must be of type "${expected}", but got "${value}".`);
        Object.setPrototypeOf(this, InvalidOptionValueError.prototype);
    }
}
class UnexpectedOptionValueError extends ValidationError {
    constructor(option, value){
        super(`Option "${getFlag(option)}" doesn't take a value, but got "${value}".`);
        Object.setPrototypeOf(this, InvalidOptionValueError.prototype);
    }
}
class OptionNotCombinableError extends ValidationError {
    constructor(option){
        super(`Option "${getFlag(option)}" cannot be combined with other options.`);
        Object.setPrototypeOf(this, OptionNotCombinableError.prototype);
    }
}
class ConflictingOptionError extends ValidationError {
    constructor(option, conflictingOption){
        super(`Option "${getFlag(option)}" conflicts with option "${getFlag(conflictingOption)}".`);
        Object.setPrototypeOf(this, ConflictingOptionError.prototype);
    }
}
class DependingOptionError extends ValidationError {
    constructor(option, dependingOption){
        super(`Option "${getFlag(option)}" depends on option "${getFlag(dependingOption)}".`);
        Object.setPrototypeOf(this, DependingOptionError.prototype);
    }
}
class MissingRequiredOptionError extends ValidationError {
    constructor(option){
        super(`Missing required option "${getFlag(option)}".`);
        Object.setPrototypeOf(this, MissingRequiredOptionError.prototype);
    }
}
class UnexpectedRequiredArgumentError extends ValidationError {
    constructor(arg){
        super(`An required argument cannot follow an optional argument, but "${arg}"  is defined as required.`);
        Object.setPrototypeOf(this, UnexpectedRequiredArgumentError.prototype);
    }
}
class UnexpectedArgumentAfterVariadicArgumentError extends ValidationError {
    constructor(arg){
        super(`An argument cannot follow an variadic argument, but got "${arg}".`);
        Object.setPrototypeOf(this, UnexpectedArgumentAfterVariadicArgumentError.prototype);
    }
}
class InvalidTypeError extends ValidationError {
    constructor({ label, name, value, type }, expected){
        super(`${label} "${name}" must be of type "${type}", but got "${value}".` + (expected ? ` Expected values: ${expected.map((value)=>`"${value}"`).join(", ")}` : ""));
        Object.setPrototypeOf(this, MissingOptionValueError.prototype);
    }
}
var OptionType;
(function(OptionType) {
    OptionType["STRING"] = "string";
    OptionType["NUMBER"] = "number";
    OptionType["INTEGER"] = "integer";
    OptionType["BOOLEAN"] = "boolean";
})(OptionType || (OptionType = {}));
const __boolean = (type)=>{
    if (~[
        "1",
        "true"
    ].indexOf(type.value)) {
        return true;
    }
    if (~[
        "0",
        "false"
    ].indexOf(type.value)) {
        return false;
    }
    throw new InvalidTypeError(type, [
        "true",
        "false",
        "1",
        "0"
    ]);
};
const number = (type)=>{
    const value = Number(type.value);
    if (Number.isFinite(value)) {
        return value;
    }
    throw new InvalidTypeError(type);
};
const string = ({ value })=>{
    return value;
};
function validateFlags(ctx, opts, options = new Map()) {
    if (!opts.flags) {
        return;
    }
    setDefaultValues(ctx, opts);
    const optionNames = Object.keys(ctx.flags);
    if (!optionNames.length && opts.allowEmpty) {
        return;
    }
    if (ctx.standalone) {
        validateStandaloneOption(ctx, options, optionNames);
        return;
    }
    for (const [name, option] of options){
        validateUnknownOption(option, opts);
        validateConflictingOptions(ctx, option);
        validateDependingOptions(ctx, option);
        validateRequiredValues(ctx, option, name);
    }
    validateRequiredOptions(ctx, options, opts);
}
function validateUnknownOption(option, opts) {
    if (!getOption(opts.flags ?? [], option.name)) {
        throw new UnknownOptionError(option.name, opts.flags ?? []);
    }
}
function setDefaultValues(ctx, opts) {
    if (!opts.flags?.length) {
        return;
    }
    for (const option of opts.flags){
        let name;
        let defaultValue = undefined;
        if (option.name.startsWith("no-")) {
            const propName = option.name.replace(/^no-/, "");
            if (typeof ctx.flags[propName] !== "undefined") {
                continue;
            }
            const positiveOption = getOption(opts.flags, propName);
            if (positiveOption) {
                continue;
            }
            name = paramCaseToCamelCase(propName);
            defaultValue = true;
        }
        if (!name) {
            name = paramCaseToCamelCase(option.name);
        }
        const hasDefaultValue = (!opts.ignoreDefaults || typeof opts.ignoreDefaults[name] === "undefined") && typeof ctx.flags[name] === "undefined" && (typeof option.default !== "undefined" || typeof defaultValue !== "undefined");
        if (hasDefaultValue) {
            ctx.flags[name] = getDefaultValue(option) ?? defaultValue;
            ctx.defaults[option.name] = true;
            if (typeof option.value === "function") {
                ctx.flags[name] = option.value(ctx.flags[name]);
            }
        }
    }
}
function validateStandaloneOption(ctx, options, optionNames) {
    if (!ctx.standalone || optionNames.length === 1) {
        return;
    }
    for (const [_, opt] of options){
        if (!ctx.defaults[opt.name] && opt !== ctx.standalone) {
            throw new OptionNotCombinableError(ctx.standalone.name);
        }
    }
}
function validateConflictingOptions(ctx, option) {
    if (!option.conflicts?.length) {
        return;
    }
    for (const flag of option.conflicts){
        if (isset(flag, ctx.flags)) {
            throw new ConflictingOptionError(option.name, flag);
        }
    }
}
function validateDependingOptions(ctx, option) {
    if (!option.depends) {
        return;
    }
    for (const flag of option.depends){
        if (!isset(flag, ctx.flags) && !ctx.defaults[option.name]) {
            throw new DependingOptionError(option.name, flag);
        }
    }
}
function validateRequiredValues(ctx, option, name) {
    if (!option.args) {
        return;
    }
    const isArray = option.args.length > 1;
    for(let i = 0; i < option.args.length; i++){
        const arg = option.args[i];
        if (arg.optional) {
            continue;
        }
        const hasValue = isArray ? typeof ctx.flags[name][i] !== "undefined" : typeof ctx.flags[name] !== "undefined";
        if (!hasValue) {
            throw new MissingOptionValueError(option.name);
        }
    }
}
function validateRequiredOptions(ctx, options, opts) {
    if (!opts.flags?.length) {
        return;
    }
    const optionsValues = [
        ...options.values()
    ];
    for (const option of opts.flags){
        if (!option.required || paramCaseToCamelCase(option.name) in ctx.flags) {
            continue;
        }
        const conflicts = option.conflicts ?? [];
        const hasConflict = conflicts.find((flag)=>!!ctx.flags[flag]);
        const hasConflicts = hasConflict || optionsValues.find((opt)=>opt.conflicts?.find((flag)=>flag === option.name));
        if (hasConflicts) {
            continue;
        }
        throw new MissingRequiredOptionError(option.name);
    }
}
function isset(flagName, flags) {
    const name = paramCaseToCamelCase(flagName);
    return typeof flags[name] !== "undefined";
}
const integer = (type)=>{
    const value = Number(type.value);
    if (Number.isInteger(value)) {
        return value;
    }
    throw new InvalidTypeError(type);
};
const DefaultTypes = {
    string,
    number,
    integer,
    boolean: __boolean
};
function parseFlags(argsOrCtx, opts = {}) {
    let args;
    let ctx;
    if (Array.isArray(argsOrCtx)) {
        ctx = {};
        args = argsOrCtx;
    } else {
        ctx = argsOrCtx;
        args = argsOrCtx.unknown;
        argsOrCtx.unknown = [];
    }
    args = args.slice();
    ctx.flags ??= {};
    ctx.literal ??= [];
    ctx.unknown ??= [];
    ctx.stopEarly = false;
    ctx.stopOnUnknown = false;
    ctx.defaults ??= {};
    opts.dotted ??= true;
    validateOptions(opts);
    const options = parseArgs(ctx, args, opts);
    validateFlags(ctx, opts, options);
    if (opts.dotted) {
        parseDottedOptions(ctx);
    }
    return ctx;
}
function validateOptions(opts) {
    opts.flags?.forEach((opt)=>{
        opt.depends?.forEach((flag)=>{
            if (!opts.flags || !getOption(opts.flags, flag)) {
                throw new UnknownRequiredOptionError(flag, opts.flags ?? []);
            }
        });
        opt.conflicts?.forEach((flag)=>{
            if (!opts.flags || !getOption(opts.flags, flag)) {
                throw new UnknownConflictingOptionError(flag, opts.flags ?? []);
            }
        });
    });
}
function parseArgs(ctx, args, opts) {
    const optionsMap = new Map();
    let inLiteral = false;
    for(let argsIndex = 0; argsIndex < args.length; argsIndex++){
        let option;
        let current = args[argsIndex];
        let currentValue;
        let negate = false;
        if (inLiteral) {
            ctx.literal.push(current);
            continue;
        } else if (current === "--") {
            inLiteral = true;
            continue;
        } else if (ctx.stopEarly || ctx.stopOnUnknown) {
            ctx.unknown.push(current);
            continue;
        }
        const isFlag = current.length > 1 && current[0] === "-";
        if (!isFlag) {
            if (opts.stopEarly) {
                ctx.stopEarly = true;
            }
            ctx.unknown.push(current);
            continue;
        }
        const isShort = current[1] !== "-";
        const isLong = isShort ? false : current.length > 3 && current[2] !== "-";
        if (!isShort && !isLong) {
            throw new InvalidOptionError(current, opts.flags ?? []);
        }
        if (isShort && current.length > 2 && current[2] !== ".") {
            args.splice(argsIndex, 1, ...splitFlags(current));
            current = args[argsIndex];
        } else if (isLong && current.startsWith("--no-")) {
            negate = true;
        }
        const equalSignIndex = current.indexOf("=");
        if (equalSignIndex !== -1) {
            currentValue = current.slice(equalSignIndex + 1) || undefined;
            current = current.slice(0, equalSignIndex);
        }
        if (opts.flags) {
            option = getOption(opts.flags, current);
            if (!option) {
                const name = current.replace(/^-+/, "");
                option = matchWildCardOptions(name, opts.flags);
                if (!option) {
                    if (opts.stopOnUnknown) {
                        ctx.stopOnUnknown = true;
                        ctx.unknown.push(args[argsIndex]);
                        continue;
                    }
                    throw new UnknownOptionError(current, opts.flags);
                }
            }
        } else {
            option = {
                name: current.replace(/^-+/, ""),
                optionalValue: true,
                type: OptionType.STRING
            };
        }
        if (option.standalone) {
            ctx.standalone = option;
        }
        const positiveName = negate ? option.name.replace(/^no-?/, "") : option.name;
        const propName = paramCaseToCamelCase(positiveName);
        if (typeof ctx.flags[propName] !== "undefined") {
            if (!opts.flags?.length) {
                option.collect = true;
            } else if (!option.collect && !ctx.defaults[option.name]) {
                throw new DuplicateOptionError(current);
            }
        }
        if (option.type && !option.args?.length) {
            option.args = [
                {
                    type: option.type,
                    optional: option.optionalValue,
                    variadic: option.variadic,
                    list: option.list,
                    separator: option.separator
                }
            ];
        }
        if (opts.flags?.length && !option.args?.length && typeof currentValue !== "undefined") {
            throw new UnexpectedOptionValueError(option.name, currentValue);
        }
        let optionArgsIndex = 0;
        let inOptionalArg = false;
        const next = ()=>currentValue ?? args[argsIndex + 1];
        const previous = ctx.flags[propName];
        parseNext(option);
        if (typeof ctx.flags[propName] === "undefined") {
            if (option.args?.length && !option.args?.[optionArgsIndex].optional) {
                throw new MissingOptionValueError(option.name);
            } else if (typeof option.default !== "undefined" && (option.type || option.value || option.args?.length)) {
                ctx.flags[propName] = getDefaultValue(option);
            } else {
                setFlagValue(true);
            }
        }
        if (option.value) {
            const value = option.value(ctx.flags[propName], previous);
            setFlagValue(value);
        } else if (option.collect) {
            const value = typeof previous !== "undefined" ? Array.isArray(previous) ? previous : [
                previous
            ] : [];
            value.push(ctx.flags[propName]);
            setFlagValue(value);
        }
        optionsMap.set(propName, option);
        opts.option?.(option, ctx.flags[propName]);
        function parseNext(option) {
            if (negate) {
                setFlagValue(false);
                return;
            } else if (!option.args?.length) {
                setFlagValue(undefined);
                return;
            }
            const arg = option.args[optionArgsIndex];
            if (!arg) {
                const flag = next();
                throw new UnknownOptionError(flag, opts.flags ?? []);
            }
            if (!arg.type) {
                arg.type = OptionType.BOOLEAN;
            }
            if (!option.args?.length && arg.type === OptionType.BOOLEAN && arg.optional === undefined) {
                arg.optional = true;
            }
            if (arg.optional) {
                inOptionalArg = true;
            } else if (inOptionalArg) {
                throw new UnexpectedRequiredArgumentError(option.name);
            }
            let result;
            let increase = false;
            if (arg.list && hasNext(arg)) {
                const parsed = next().split(arg.separator || ",").map((nextValue)=>{
                    const value = parseValue(option, arg, nextValue);
                    if (typeof value === "undefined") {
                        throw new InvalidOptionValueError(option.name, arg.type ?? "?", nextValue);
                    }
                    return value;
                });
                if (parsed?.length) {
                    result = parsed;
                }
            } else {
                if (hasNext(arg)) {
                    result = parseValue(option, arg, next());
                } else if (arg.optional && arg.type === OptionType.BOOLEAN) {
                    result = true;
                }
            }
            if (increase && typeof currentValue === "undefined") {
                argsIndex++;
                if (!arg.variadic) {
                    optionArgsIndex++;
                } else if (option.args[optionArgsIndex + 1]) {
                    throw new UnexpectedArgumentAfterVariadicArgumentError(next());
                }
            }
            if (typeof result !== "undefined" && (option.args.length > 1 || arg.variadic)) {
                if (!ctx.flags[propName]) {
                    setFlagValue([]);
                }
                ctx.flags[propName].push(result);
                if (hasNext(arg)) {
                    parseNext(option);
                }
            } else {
                setFlagValue(result);
            }
            function hasNext(arg) {
                if (!option.args?.length) {
                    return false;
                }
                const nextValue = currentValue ?? args[argsIndex + 1];
                if (!nextValue) {
                    return false;
                }
                if (option.args.length > 1 && optionArgsIndex >= option.args.length) {
                    return false;
                }
                if (!arg.optional) {
                    return true;
                }
                if (option.equalsSign && arg.optional && !arg.variadic && typeof currentValue === "undefined") {
                    return false;
                }
                if (arg.optional || arg.variadic) {
                    return nextValue[0] !== "-" || typeof currentValue !== "undefined" || arg.type === OptionType.NUMBER && !isNaN(Number(nextValue));
                }
                return false;
            }
            function parseValue(option, arg, value) {
                const result = opts.parse ? opts.parse({
                    label: "Option",
                    type: arg.type || OptionType.STRING,
                    name: `--${option.name}`,
                    value
                }) : parseDefaultType(option, arg, value);
                if (typeof result !== "undefined") {
                    increase = true;
                }
                return result;
            }
        }
        function setFlagValue(value) {
            ctx.flags[propName] = value;
            if (ctx.defaults[propName]) {
                delete ctx.defaults[propName];
            }
        }
    }
    return optionsMap;
}
function parseDottedOptions(ctx) {
    ctx.flags = Object.keys(ctx.flags).reduce((result, key)=>{
        if (~key.indexOf(".")) {
            key.split(".").reduce((result, subKey, index, parts)=>{
                if (index === parts.length - 1) {
                    result[subKey] = ctx.flags[key];
                } else {
                    result[subKey] = result[subKey] ?? {};
                }
                return result[subKey];
            }, result);
        } else {
            result[key] = ctx.flags[key];
        }
        return result;
    }, {});
}
function splitFlags(flag) {
    flag = flag.slice(1);
    const normalized = [];
    const index = flag.indexOf("=");
    const flags = (index !== -1 ? flag.slice(0, index) : flag).split("");
    if (isNaN(Number(flag[flag.length - 1]))) {
        flags.forEach((val)=>normalized.push(`-${val}`));
    } else {
        normalized.push(`-${flags.shift()}`);
        if (flags.length) {
            normalized.push(flags.join(""));
        }
    }
    if (index !== -1) {
        normalized[normalized.length - 1] += flag.slice(index);
    }
    return normalized;
}
function parseDefaultType(option, arg, value) {
    const type = arg.type || OptionType.STRING;
    const parseType = DefaultTypes[type];
    if (!parseType) {
        throw new UnknownTypeError(type, Object.keys(DefaultTypes));
    }
    return parseType({
        label: "Option",
        type,
        name: `--${option.name}`,
        value
    });
}
function didYouMeanCommand(command, commands, excludes = []) {
    const commandNames = commands.map((command)=>command.getName()).filter((command)=>!excludes.includes(command));
    return didYouMean(" Did you mean command", command, commandNames);
}
const ARGUMENT_REGEX = /^[<\[].+[\]>]$/;
const ARGUMENT_DETAILS_REGEX = /[<\[:>\]]/;
function splitArguments(args) {
    const parts = args.trim().split(/[, =] */g);
    const typeParts = [];
    while(parts[parts.length - 1] && ARGUMENT_REGEX.test(parts[parts.length - 1])){
        typeParts.unshift(parts.pop());
    }
    const typeDefinition = typeParts.join(" ");
    return {
        flags: parts,
        typeDefinition,
        equalsSign: args.includes("=")
    };
}
function parseArgumentsDefinition(argsDefinition, validate = true, all) {
    const argumentDetails = [];
    let hasOptional = false;
    let hasVariadic = false;
    const parts = argsDefinition.split(/ +/);
    for (const arg of parts){
        if (validate && hasVariadic) {
            throw new UnexpectedArgumentAfterVariadicArgumentError(arg);
        }
        const parts = arg.split(ARGUMENT_DETAILS_REGEX);
        if (!parts[1]) {
            if (all) {
                argumentDetails.push(parts[0]);
            }
            continue;
        }
        const type = parts[2] || OptionType.STRING;
        const details = {
            optional: arg[0] === "[",
            name: parts[1],
            action: parts[3] || type,
            variadic: false,
            list: type ? arg.indexOf(type + "[]") !== -1 : false,
            type
        };
        if (validate && !details.optional && hasOptional) {
            throw new UnexpectedRequiredArgumentError(details.name);
        }
        if (arg[0] === "[") {
            hasOptional = true;
        }
        if (details.name.length > 3) {
            const istVariadicLeft = details.name.slice(0, 3) === "...";
            const istVariadicRight = details.name.slice(-3) === "...";
            hasVariadic = details.variadic = istVariadicLeft || istVariadicRight;
            if (istVariadicLeft) {
                details.name = details.name.slice(3);
            } else if (istVariadicRight) {
                details.name = details.name.slice(0, -3);
            }
        }
        argumentDetails.push(details);
    }
    return argumentDetails;
}
function dedent(str) {
    const lines = str.split(/\r?\n|\r/g);
    let text = "";
    let indent = 0;
    for (const line of lines){
        if (text || line.trim()) {
            if (!text) {
                text = line.trimStart();
                indent = line.length - text.length;
            } else {
                text += line.slice(indent);
            }
            text += "\n";
        }
    }
    return text.trimEnd();
}
function getDescription(description, __short) {
    return __short ? description.trim().split("\n", 1)[0].trim() : dedent(description);
}
class CommandError extends Error {
    constructor(message){
        super(message);
        Object.setPrototypeOf(this, CommandError.prototype);
    }
}
class ValidationError1 extends CommandError {
    exitCode;
    cmd;
    constructor(message, { exitCode } = {}){
        super(message);
        Object.setPrototypeOf(this, ValidationError1.prototype);
        this.exitCode = exitCode ?? 2;
    }
}
class DuplicateOptionNameError extends CommandError {
    constructor(optionName, commandName){
        super(`An option with name '${bold(getFlag(optionName))}' is already registered on command '${bold(commandName)}'. If it is intended to override the option, set the '${bold("override")}' option of the '${bold("option")}' method to true.`);
        Object.setPrototypeOf(this, DuplicateOptionNameError.prototype);
    }
}
class MissingCommandNameError extends CommandError {
    constructor(){
        super("Missing command name.");
        Object.setPrototypeOf(this, MissingCommandNameError.prototype);
    }
}
class DuplicateCommandNameError extends CommandError {
    constructor(name){
        super(`Duplicate command name "${name}".`);
        Object.setPrototypeOf(this, DuplicateCommandNameError.prototype);
    }
}
class DuplicateCommandAliasError extends CommandError {
    constructor(alias){
        super(`Duplicate command alias "${alias}".`);
        Object.setPrototypeOf(this, DuplicateCommandAliasError.prototype);
    }
}
class CommandNotFoundError extends CommandError {
    constructor(name, commands, excluded){
        super(`Unknown command "${name}".${didYouMeanCommand(name, commands, excluded)}`);
        Object.setPrototypeOf(this, CommandNotFoundError.prototype);
    }
}
class DuplicateTypeError extends CommandError {
    constructor(name){
        super(`Type with name "${name}" already exists.`);
        Object.setPrototypeOf(this, DuplicateTypeError.prototype);
    }
}
class DuplicateCompletionError extends CommandError {
    constructor(name){
        super(`Completion with name "${name}" already exists.`);
        Object.setPrototypeOf(this, DuplicateCompletionError.prototype);
    }
}
class DuplicateExampleError extends CommandError {
    constructor(name){
        super(`Example with name "${name}" already exists.`);
        Object.setPrototypeOf(this, DuplicateExampleError.prototype);
    }
}
class DuplicateEnvVarError extends CommandError {
    constructor(name){
        super(`Environment variable with name "${name}" already exists.`);
        Object.setPrototypeOf(this, DuplicateEnvVarError.prototype);
    }
}
class MissingRequiredEnvVarError extends ValidationError1 {
    constructor(envVar){
        super(`Missing required environment variable "${envVar.names[0]}".`);
        Object.setPrototypeOf(this, MissingRequiredEnvVarError.prototype);
    }
}
class TooManyEnvVarValuesError extends CommandError {
    constructor(name){
        super(`An environment variable can only have one value, but "${name}" has more than one.`);
        Object.setPrototypeOf(this, TooManyEnvVarValuesError.prototype);
    }
}
class UnexpectedOptionalEnvVarValueError extends CommandError {
    constructor(name){
        super(`An environment variable cannot have an optional value, but "${name}" is defined as optional.`);
        Object.setPrototypeOf(this, UnexpectedOptionalEnvVarValueError.prototype);
    }
}
class UnexpectedVariadicEnvVarValueError extends CommandError {
    constructor(name){
        super(`An environment variable cannot have an variadic value, but "${name}" is defined as variadic.`);
        Object.setPrototypeOf(this, UnexpectedVariadicEnvVarValueError.prototype);
    }
}
class DefaultCommandNotFoundError extends CommandError {
    constructor(name, commands){
        super(`Default command "${name}" not found.${didYouMeanCommand(name, commands)}`);
        Object.setPrototypeOf(this, DefaultCommandNotFoundError.prototype);
    }
}
class CommandExecutableNotFoundError extends CommandError {
    constructor(name){
        super(`Command executable not found: ${name}`);
        Object.setPrototypeOf(this, CommandExecutableNotFoundError.prototype);
    }
}
class UnknownCommandError extends ValidationError1 {
    constructor(name, commands, excluded){
        super(`Unknown command "${name}".${didYouMeanCommand(name, commands, excluded)}`);
        Object.setPrototypeOf(this, UnknownCommandError.prototype);
    }
}
class NoArgumentsAllowedError extends ValidationError1 {
    constructor(name){
        super(`No arguments allowed for command "${name}".`);
        Object.setPrototypeOf(this, NoArgumentsAllowedError.prototype);
    }
}
class MissingArgumentsError extends ValidationError1 {
    constructor(names){
        super(`Missing argument(s): ${names.join(", ")}`);
        Object.setPrototypeOf(this, MissingArgumentsError.prototype);
    }
}
class MissingArgumentError extends ValidationError1 {
    constructor(name){
        super(`Missing argument: ${name}`);
        Object.setPrototypeOf(this, MissingArgumentError.prototype);
    }
}
class TooManyArgumentsError extends ValidationError1 {
    constructor(args){
        super(`Too many arguments: ${args.join(" ")}`);
        Object.setPrototypeOf(this, TooManyArgumentsError.prototype);
    }
}
class Type {
}
class BooleanType extends Type {
    parse(type) {
        return __boolean(type);
    }
    complete() {
        return [
            "true",
            "false"
        ];
    }
}
class StringType extends Type {
    parse(type) {
        return string(type);
    }
}
class FileType extends StringType {
    constructor(){
        super();
    }
}
class IntegerType extends Type {
    parse(type) {
        return integer(type);
    }
}
class NumberType extends Type {
    parse(type) {
        return number(type);
    }
}
const border = {
    top: "─",
    topMid: "┬",
    topLeft: "┌",
    topRight: "┐",
    bottom: "─",
    bottomMid: "┴",
    bottomLeft: "└",
    bottomRight: "┘",
    left: "│",
    leftMid: "├",
    mid: "─",
    midMid: "┼",
    right: "│",
    rightMid: "┤",
    middle: "│"
};
class Cell {
    value;
    options;
    get length() {
        return this.toString().length;
    }
    static from(value) {
        let cell;
        if (value instanceof Cell) {
            cell = new this(value.getValue());
            cell.options = {
                ...value.options
            };
        } else {
            cell = new this(value);
        }
        return cell;
    }
    constructor(value){
        this.value = value;
        this.options = {};
    }
    toString() {
        return this.value.toString();
    }
    getValue() {
        return this.value;
    }
    setValue(value) {
        this.value = value;
        return this;
    }
    clone(value) {
        return Cell.from(value ?? this);
    }
    border(enable = true, override = true) {
        if (override || typeof this.options.border === "undefined") {
            this.options.border = enable;
        }
        return this;
    }
    colSpan(span, override = true) {
        if (override || typeof this.options.colSpan === "undefined") {
            this.options.colSpan = span;
        }
        return this;
    }
    rowSpan(span, override = true) {
        if (override || typeof this.options.rowSpan === "undefined") {
            this.options.rowSpan = span;
        }
        return this;
    }
    align(direction, override = true) {
        if (override || typeof this.options.align === "undefined") {
            this.options.align = direction;
        }
        return this;
    }
    getBorder() {
        return this.options.border === true;
    }
    getColSpan() {
        return typeof this.options.colSpan === "number" && this.options.colSpan > 0 ? this.options.colSpan : 1;
    }
    getRowSpan() {
        return typeof this.options.rowSpan === "number" && this.options.rowSpan > 0 ? this.options.rowSpan : 1;
    }
    getAlign() {
        return this.options.align ?? "left";
    }
}
class Column {
    static from(options) {
        const opts = options instanceof Column ? options.opts : options;
        return new Column().options(opts);
    }
    opts = {};
    options(options) {
        Object.assign(this.opts, options);
        return this;
    }
    minWidth(width) {
        this.opts.minWidth = width;
        return this;
    }
    maxWidth(width) {
        this.opts.maxWidth = width;
        return this;
    }
    border(border = true) {
        this.opts.border = border;
        return this;
    }
    padding(padding) {
        this.opts.padding = padding;
        return this;
    }
    align(direction) {
        this.opts.align = direction;
        return this;
    }
    getMinWidth() {
        return this.opts.minWidth;
    }
    getMaxWidth() {
        return this.opts.maxWidth;
    }
    getBorder() {
        return this.opts.border;
    }
    getPadding() {
        return this.opts.padding;
    }
    getAlign() {
        return this.opts.align;
    }
}
const __default1 = JSON.parse("{\n  \"UNICODE_VERSION\": \"15.0.0\",\n  \"tables\": [\n    {\n      \"d\": \"AAECAwQFBgcICQoLDA0OAw8DDwkQCRESERIA\",\n      \"r\": \"AQEBAgEBAQEBAQEBAQEBBwEHAVABBwcBBwF4\"\n    },\n    {\n      \"d\": \"AAECAwQFBgcGCAYJCgsMDQ4PEAYREhMUBhUWFxgZGhscHR4fICEiIyIkJSYnKCkqJSssLS4vMDEyMzQ1Njc4OToGOzwKBj0GPj9AQUIGQwZEBkVGR0hJSktMTQZOBgoGT1BRUlNUVVZXWFkGWgZbBlxdXl1fYGFiY2RlZmdoBmlqBmsGAQZsBm1uO29wcXI7czt0dXZ3OwY7eHkGent8Bn0Gfn+AgYKDhIWGBoc7iAZdO4kGiosGAXGMBo0GjgaPBpAGkQaSBpMGlJUGlpcGmJmam5ydnp+gLgahLKIGo6SlpganqKmqqwasBq0Grq8GsLGyswa0BrUGtre4Brm6uwZHvAa9vga/wME7wjvDxAbFO8bHO8gGyQbKywbMzQbOBs/Q0QbSBr8GvgbT1AbUBtUG1gbXBtjZ2tsG3N0G3t/g4eLjO+Tl5ufoO+k76gbrBuztOwbu7/AGO+XxCgYKCwZd8g==\",\n      \"r\": \"AQEBAQEBAQEBAQEBAQEBAQEBAQMBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECBQEOAQEBAQEBAQEBAwEBAQEBAQEBAQIBAwEIAQEBAQEBAQEBAQEBAQIBAQEBAQEBAQEBAQEBAQEBDQEBBQEBAQEBAgEBAwEBAQEBAQEBAQEBbQHaAQEFAQEBBAECAQEBAQEBAQEBAwGuASFkCAELAQEBAQEBAQEHAQMBAQEaAQIBCAEFAQEBAQEBAQEBAQEBAQEBAQEBAQECAQEBAQIBAQEBAQEBAwEDAQEBAQEBAQUBAQEBAQEBBAEBAVIBAdkBARABAQFfARMBAYoBBAEBBQEmAUkBAQcBAQIBHgEBARUBAQEBAQUBAQcBDwEBARoBAgEBAQEBAQECAQEBAQEBAQEBAQEBAQEBAQMBBAEBAgEBAQEUfwEBAQIDAXj/AQ==\"\n    },\n    {\n      \"d\": \"AFUVAF3Xd3X/93//VXVVV9VX9V91f1/31X93XVXdVdVV9dVV/VVX1X9X/131VfXVVXV3V1VdVV1V1/1dV1X/3VUAVf3/3/9fVf3/3/9fVV1V/11VFQBQVQEAEEEQVQBQVQBAVFUVAFVUVQUAEAAUBFBVFVFVAEBVBQBUVRUAVVFVBRAAAVBVAVVQVQBVBQBAVUVUAQBUUQEAVQVVUVVUAVRVUVUFVUVBVVRBFRRQUVVQUVUBEFRRVQVVBQBRVRQBVFVRVUFVBVVFVVRVUVVUVQRUBQRQVUFVBVVFVVBVBVVQVRVUAVRVUVUFVVFVRVUFRFVRAEBVFQBAVVEAVFUAQFVQVRFRVQEAQAAEVQEAAQBUVUVVAQQAQVVQBVRVAVRVRUFVUVVRVaoAVQFVBVRVBVUFVQVVEABQVUUBAFVRVRUAVUFVUVVAFVRVRVUBVRUUVUUAQEQBAFQVABRVAEBVAFUEQFRFVRUAVVBVBVAQUFVFUBFQVQAFVUAABABUUVVUUFUVANd/X3//BUD3XdV1VQAEAFVXVdX9V1VXVQBUVdVdVdV1VX111VXVV9V//1X/X1VdVf9fVV9VdVdV1VX31dfVXXX9193/d1X/VV9VV3VVX//1VfVVXVVdVdVVdVWlVWlVqVaWVf/f/1X/Vf/1X1Xf/19V9VVf9df1X1X1X1XVVWlVfV31VVpVd1V3VapV33/fVZVVlVX1WVWlVelV+v/v//7/31Xv/6/77/tVWaVVVlVdVWaVmlX1/1WpVVZVlVWVVlVW+V9VFVBVAKqaqlWqWlWqVaoKoKpqqapqgapVqaqpqmqqVapqqv+qVqpqVRVAAFBVBVVQVUUVVUFVVFVQVQBQVRVVBQBQVRUAUFWqVkBVFQVQVVFVAUBBVRVVVFVUVQQUVAVRVVBVRVVRVFFVqlVFVQCqWlUAqmqqaqpVqlZVqmpVAV1VUVVUVQVAVQFBVQBVQBVVQVUAVRVUVQFVBQBUVQVQVVFVAEBVFFRVFVBVFUBBUUVVUVVAVRUAAQBUVRVVUFUFAEBVARRVFVAEVUVVFQBAVVRVBQBUAFRVAAVEVUVVFQBEFQRVBVBVEFRVUFUVAEARVFUVUQAQVQEFEABVFQBBVRVEFVUABVVUVQEAQFUVABRAVRVVAUABVQUAQFBVAEAAEFUFAAUABEFVAUBFEAAQVVARVRVUVVBVBUBVRFVUFQBQVQBUVQBAVRVVFUBVqlRVWlWqVapaVapWVaqpqmmqalVlVWpZVapVqlVBAFUAUABAVRVQVRUAQAEAVQVQVQVUVQBAFQBUVVFVVFUVAAEAVQBAABQAEARAVUVVAFUAQFUAQFVWVZVV/39V/1//X1X/76uq6v9XVWpVqlWqVlVaVapaVapWVamqmqqmqlWqapWqVapWqmqmqpaqWlWVaqpVZVVpVVZVlapVqlpVVmqpVapVlVZVqlZVqlVWVapqqpqqVapWqlZVqpqqWlWlqlWqVlWqVlVRVQD/Xw==\",\n      \"r\": \"CBcBCAEBAQEBAQEBAQECAQEBAQEBAQEBAQEBAQMBAQECAQEBAQEBAQEBAQEBBAEBGAEDAQwBAwEIAQEBAQEBAQgcCAEDAQEBAQEDAQEBDQEDEAELAQEBEQEKAQEBDgEBAgIBAQoBBQQBCAEBAQEBAQEHAQEHBgEWAQIBDQECAgEFAQECAgEKAQ0BAQIKAQ0BDQEBAQEBAQEBAgEHAQ4BAQEBAQQBBgEBDgEBAQEBAQcBAQIBAQEBBAEFAQEBDgEBAQEBAQECAQcBDwECAQwCDQEBAQEBAQECAQgBAQEEAQcBDQEBAQEBAQQBBwERAQEBARYBAQECAQEBGAECAQIBARIBBgEBDQECAQEBAQECAQgBAQEZAQEBAgYBAQEDAQECAQEBAQMBCBgIBwEMAQEGAQcBBwEQAQEBAQEBAgIBCgEBDQEIAQ0BAQEBAQEBBgEBDgEBAQEBAQEBAgEMBwEMAQwBAQEBCQECAwEHAQEBAQ0BAQEBDgIBBgEDAQEBAQEBAQMBAQEBAgEBAQEBAQEBCAEBAgEBAQEBAQkBCAgBAwECAQEBAgEBAQkBAQEBAwECAQMBAQIBBwEFAQEDAQYBAQEBAgEBAQEBAQEBAQECAgEDAQECBAIDAgIBBQEEAQEBAwEPAQEBCyIBCAEJAwQBAQIBAQEBAgECAQEBAQMBAQEBAwEBAQEBAQEBAQgBAQMDAgEBAwEEAQIBAQEBBAEBAQEBAQECAQEBAQEBAQEBAQEHAQQBAwEBAQcBAgUBBgECAQYBAQwBAQEUAQELCAYBFgMFAQYDAQoBAQMBARQBAQkBAQoBBgEVAwsBCgIPAQ0BGQEBAgEHARQBAwIBBgEBAQUBBgQBAgEJAQEBBQECAQMHAQELAQECCQEQAQECAgECAQsBDAEBAQEBCgEBAQsBAQEECQ4BCAQCAQEECAEEAQEFCAEPAQEEAQEPAQgBFAEBAQEBAQEKAQEJAQ8BEAEBEwEBAQIBCwEBDgENAwEKAQEBAQELAQEBAQECAQwBCAEBAQEBDgEDAQwBAQECAQEXAQEBAQEHAgEBBQEIAQEBAQEQAgEBBQEUAQEBAQEbAQEBAQEGARQBAQEBARkBAQEBCQEBAQEQAQIBDwEBARQBAQEBBwEBAQkBAQEBAQECAQEBCwECAQEVAQEBAQQBBQEBAQEOAQEBAQEBEgEBFgEBAgEMAQEBAQ8BAQMBFgEBDgEBBQEPAQETAQECAQMOAgUBCgIBGQEBAQEIAQMBBwEBAwECEwgBAQcLAQUBFwEBAQEDAQEBBwEBBAEBDg0BAQwBAQEDAQQBAQEDBAEBBAEBAQEBEAEPAQgBAQsBAQ4BEQEMAgEBBwEOAQEHAQEBAQQBBAEDCwECAQEBAwEBBggBAgEBAREBBQMKAQEBAwQCEQEBHgEPAQIBAQYEAQYBAwEUAQUMAQEBAQEBAQECAQEBAgEIAwEBBgsBAgEODAMBAgEBCwEBAQEBAwECAQECAQEBBwgPAQ==\"\n    }\n  ]\n}");
function runLengthDecode({ d, r }) {
    const data = atob(d);
    const runLengths = atob(r);
    let out = "";
    for (const [i, ch] of [
        ...runLengths
    ].entries()){
        out += data[i].repeat(ch.codePointAt(0));
    }
    return Uint8Array.from([
        ...out
    ].map((x)=>x.codePointAt(0)));
}
let tables = null;
function lookupWidth(cp) {
    if (!tables) tables = __default1.tables.map(runLengthDecode);
    const t1Offset = tables[0][cp >> 13 & 0xff];
    const t2Offset = tables[1][128 * t1Offset + (cp >> 6 & 0x7f)];
    const packedWidths = tables[2][16 * t2Offset + (cp >> 2 & 0xf)];
    const width = packedWidths >> 2 * (cp & 0b11) & 0b11;
    return width === 3 ? 1 : width;
}
const cache = new Map();
function charWidth(ch) {
    if (cache.has(ch)) return cache.get(ch);
    const cp = ch.codePointAt(0);
    let v = null;
    if (cp < 0x7f) {
        v = cp >= 0x20 ? 1 : cp === 0 ? 0 : null;
    } else if (cp >= 0xa0) {
        v = lookupWidth(cp);
    } else {
        v = null;
    }
    cache.set(ch, v);
    return v;
}
function unicodeWidth(str) {
    return [
        ...str
    ].map((ch)=>charWidth(ch) ?? 0).reduce((a, b)=>a + b, 0);
}
const strLength = (str)=>{
    return unicodeWidth(stripColor(str));
};
function consumeWords(length, content) {
    let consumed = "";
    const words = content.split("\n")[0]?.split(/ /g);
    for(let i = 0; i < words.length; i++){
        const word = words[i];
        if (consumed) {
            const nextLength = strLength(word);
            const consumedLength = strLength(consumed);
            if (consumedLength + nextLength >= length) {
                break;
            }
        }
        consumed += (i > 0 ? " " : "") + word;
    }
    return consumed;
}
function longest(index, rows, maxWidth) {
    const cellLengths = rows.map((row)=>{
        const cell = row[index];
        const cellValue = cell instanceof Cell && cell.getColSpan() > 1 ? "" : cell?.toString() || "";
        return cellValue.split("\n").map((line)=>{
            const str = typeof maxWidth === "undefined" ? line : consumeWords(maxWidth, line);
            return strLength(str) || 0;
        });
    }).flat();
    return Math.max(...cellLengths);
}
class Row extends Array {
    options = {};
    static from(cells) {
        const row = new this(...cells);
        if (cells instanceof Row) {
            row.options = {
                ...cells.options
            };
        }
        return row;
    }
    clone() {
        const row = new Row(...this.map((cell)=>cell instanceof Cell ? cell.clone() : cell));
        row.options = {
            ...this.options
        };
        return row;
    }
    border(enable = true, override = true) {
        if (override || typeof this.options.border === "undefined") {
            this.options.border = enable;
        }
        return this;
    }
    align(direction, override = true) {
        if (override || typeof this.options.align === "undefined") {
            this.options.align = direction;
        }
        return this;
    }
    getBorder() {
        return this.options.border === true;
    }
    hasBorder() {
        return this.getBorder() || this.some((cell)=>cell instanceof Cell && cell.getBorder());
    }
    getAlign() {
        return this.options.align ?? "left";
    }
}
class TableLayout {
    table;
    options;
    constructor(table, options){
        this.table = table;
        this.options = options;
    }
    toString() {
        const opts = this.createLayout();
        return opts.rows.length ? this.renderRows(opts) : "";
    }
    createLayout() {
        Object.keys(this.options.chars).forEach((key)=>{
            if (typeof this.options.chars[key] !== "string") {
                this.options.chars[key] = "";
            }
        });
        const hasBodyBorder = this.table.getBorder() || this.table.hasBodyBorder();
        const hasHeaderBorder = this.table.hasHeaderBorder();
        const hasBorder = hasHeaderBorder || hasBodyBorder;
        const rows = this.#getRows();
        const columns = Math.max(...rows.map((row)=>row.length));
        for(let rowIndex = 0; rowIndex < rows.length; rowIndex++){
            const row = rows[rowIndex];
            const length = row.length;
            if (length < columns) {
                const diff = columns - length;
                for(let i = 0; i < diff; i++){
                    row.push(this.createCell(null, row, rowIndex, length + i));
                }
            }
        }
        const padding = [];
        const width = [];
        for(let colIndex = 0; colIndex < columns; colIndex++){
            const column = this.options.columns.at(colIndex);
            const minColWidth = column?.getMinWidth() ?? (Array.isArray(this.options.minColWidth) ? this.options.minColWidth[colIndex] : this.options.minColWidth);
            const maxColWidth = column?.getMaxWidth() ?? (Array.isArray(this.options.maxColWidth) ? this.options.maxColWidth[colIndex] : this.options.maxColWidth);
            const colWidth = longest(colIndex, rows, maxColWidth);
            width[colIndex] = Math.min(maxColWidth, Math.max(minColWidth, colWidth));
            padding[colIndex] = column?.getPadding() ?? (Array.isArray(this.options.padding) ? this.options.padding[colIndex] : this.options.padding);
        }
        return {
            padding,
            width,
            rows,
            columns,
            hasBorder,
            hasBodyBorder,
            hasHeaderBorder
        };
    }
    #getRows() {
        const header = this.table.getHeader();
        const rows = header ? [
            header,
            ...this.table
        ] : this.table.slice();
        const hasSpan = rows.some((row)=>row.some((cell)=>cell instanceof Cell && (cell.getColSpan() > 1 || cell.getRowSpan() > 1)));
        if (hasSpan) {
            return this.spanRows(rows);
        }
        return rows.map((row, rowIndex)=>{
            const newRow = this.createRow(row);
            for(let colIndex = 0; colIndex < row.length; colIndex++){
                newRow[colIndex] = this.createCell(row[colIndex], newRow, rowIndex, colIndex);
            }
            return newRow;
        });
    }
    spanRows(rows) {
        const rowSpan = [];
        let colSpan = 1;
        let rowIndex = -1;
        while(true){
            rowIndex++;
            if (rowIndex === rows.length && rowSpan.every((span)=>span === 1)) {
                break;
            }
            const row = rows[rowIndex] = this.createRow(rows[rowIndex] || []);
            let colIndex = -1;
            while(true){
                colIndex++;
                if (colIndex === row.length && colIndex === rowSpan.length && colSpan === 1) {
                    break;
                }
                if (colSpan > 1) {
                    colSpan--;
                    rowSpan[colIndex] = rowSpan[colIndex - 1];
                    row.splice(colIndex, this.getDeleteCount(rows, rowIndex, colIndex), row[colIndex - 1]);
                    continue;
                }
                if (rowSpan[colIndex] > 1) {
                    rowSpan[colIndex]--;
                    rows[rowIndex].splice(colIndex, this.getDeleteCount(rows, rowIndex, colIndex), rows[rowIndex - 1][colIndex]);
                    continue;
                }
                const cell = row[colIndex] = this.createCell(row[colIndex] || null, row, rowIndex, colIndex);
                colSpan = cell.getColSpan();
                rowSpan[colIndex] = cell.getRowSpan();
            }
        }
        return rows;
    }
    getDeleteCount(rows, rowIndex, colIndex) {
        return colIndex <= rows[rowIndex].length - 1 && typeof rows[rowIndex][colIndex] === "undefined" ? 1 : 0;
    }
    createRow(row) {
        return Row.from(row).border(this.table.getBorder(), false).align(this.table.getAlign(), false);
    }
    createCell(cell, row, rowIndex, colIndex) {
        const column = this.options.columns.at(colIndex);
        const isHeaderRow = this.isHeaderRow(rowIndex);
        return Cell.from(cell ?? "").border((isHeaderRow ? null : column?.getBorder()) ?? row.getBorder(), false).align((isHeaderRow ? null : column?.getAlign()) ?? row.getAlign(), false);
    }
    isHeaderRow(rowIndex) {
        return rowIndex === 0 && this.table.getHeader() !== undefined;
    }
    renderRows(opts) {
        let result = "";
        const rowSpan = new Array(opts.columns).fill(1);
        for(let rowIndex = 0; rowIndex < opts.rows.length; rowIndex++){
            result += this.renderRow(rowSpan, rowIndex, opts);
        }
        return result.slice(0, -1);
    }
    renderRow(rowSpan, rowIndex, opts, isMultiline) {
        const row = opts.rows[rowIndex];
        const prevRow = opts.rows[rowIndex - 1];
        const nextRow = opts.rows[rowIndex + 1];
        let result = "";
        let colSpan = 1;
        if (!isMultiline && rowIndex === 0 && row.hasBorder()) {
            result += this.renderBorderRow(undefined, row, rowSpan, opts);
        }
        let isMultilineRow = false;
        result += " ".repeat(this.options.indent || 0);
        for(let colIndex = 0; colIndex < opts.columns; colIndex++){
            if (colSpan > 1) {
                colSpan--;
                rowSpan[colIndex] = rowSpan[colIndex - 1];
                continue;
            }
            result += this.renderCell(colIndex, row, opts);
            if (rowSpan[colIndex] > 1) {
                if (!isMultiline) {
                    rowSpan[colIndex]--;
                }
            } else if (!prevRow || prevRow[colIndex] !== row[colIndex]) {
                rowSpan[colIndex] = row[colIndex].getRowSpan();
            }
            colSpan = row[colIndex].getColSpan();
            if (rowSpan[colIndex] === 1 && row[colIndex].length) {
                isMultilineRow = true;
            }
        }
        if (opts.columns > 0) {
            if (row[opts.columns - 1].getBorder()) {
                result += this.options.chars.right;
            } else if (opts.hasBorder) {
                result += " ";
            }
        }
        result += "\n";
        if (isMultilineRow) {
            return result + this.renderRow(rowSpan, rowIndex, opts, isMultilineRow);
        }
        if (opts.rows.length > 1 && (rowIndex === 0 && opts.hasHeaderBorder || rowIndex < opts.rows.length - 1 && opts.hasBodyBorder)) {
            result += this.renderBorderRow(row, nextRow, rowSpan, opts);
        }
        if (rowIndex === opts.rows.length - 1 && row.hasBorder()) {
            result += this.renderBorderRow(row, undefined, rowSpan, opts);
        }
        return result;
    }
    renderCell(colIndex, row, opts, noBorder) {
        let result = "";
        const prevCell = row[colIndex - 1];
        const cell = row[colIndex];
        if (!noBorder) {
            if (colIndex === 0) {
                if (cell.getBorder()) {
                    result += this.options.chars.left;
                } else if (opts.hasBorder) {
                    result += " ";
                }
            } else {
                if (cell.getBorder() || prevCell?.getBorder()) {
                    result += this.options.chars.middle;
                } else if (opts.hasBorder) {
                    result += " ";
                }
            }
        }
        let maxLength = opts.width[colIndex];
        const colSpan = cell.getColSpan();
        if (colSpan > 1) {
            for(let o = 1; o < colSpan; o++){
                maxLength += opts.width[colIndex + o] + opts.padding[colIndex + o];
                if (opts.hasBorder) {
                    maxLength += opts.padding[colIndex + o] + 1;
                }
            }
        }
        const { current, next } = this.renderCellValue(cell, maxLength);
        row[colIndex].setValue(next.getValue());
        if (opts.hasBorder) {
            result += " ".repeat(opts.padding[colIndex]);
        }
        result += current;
        if (opts.hasBorder || colIndex < opts.columns - 1) {
            result += " ".repeat(opts.padding[colIndex]);
        }
        return result;
    }
    renderCellValue(cell, maxLength) {
        const length = Math.min(maxLength, strLength(cell.toString()));
        let words = consumeWords(length, cell.toString());
        const breakWord = strLength(words) > length;
        if (breakWord) {
            words = words.slice(0, length);
        }
        const next = cell.toString().slice(words.length + (breakWord ? 0 : 1));
        const fillLength = maxLength - strLength(words);
        const align = cell.getAlign();
        let current;
        if (fillLength === 0) {
            current = words;
        } else if (align === "left") {
            current = words + " ".repeat(fillLength);
        } else if (align === "center") {
            current = " ".repeat(Math.floor(fillLength / 2)) + words + " ".repeat(Math.ceil(fillLength / 2));
        } else if (align === "right") {
            current = " ".repeat(fillLength) + words;
        } else {
            throw new Error("Unknown direction: " + align);
        }
        return {
            current,
            next: cell.clone(next)
        };
    }
    renderBorderRow(prevRow, nextRow, rowSpan, opts) {
        let result = "";
        let colSpan = 1;
        for(let colIndex = 0; colIndex < opts.columns; colIndex++){
            if (rowSpan[colIndex] > 1) {
                if (!nextRow) {
                    throw new Error("invalid layout");
                }
                if (colSpan > 1) {
                    colSpan--;
                    continue;
                }
            }
            result += this.renderBorderCell(colIndex, prevRow, nextRow, rowSpan, opts);
            colSpan = nextRow?.[colIndex].getColSpan() ?? 1;
        }
        return result.length ? " ".repeat(this.options.indent) + result + "\n" : "";
    }
    renderBorderCell(colIndex, prevRow, nextRow, rowSpan, opts) {
        const a1 = prevRow?.[colIndex - 1];
        const a2 = nextRow?.[colIndex - 1];
        const b1 = prevRow?.[colIndex];
        const b2 = nextRow?.[colIndex];
        const a1Border = !!a1?.getBorder();
        const a2Border = !!a2?.getBorder();
        const b1Border = !!b1?.getBorder();
        const b2Border = !!b2?.getBorder();
        const hasColSpan = (cell)=>(cell?.getColSpan() ?? 1) > 1;
        const hasRowSpan = (cell)=>(cell?.getRowSpan() ?? 1) > 1;
        let result = "";
        if (colIndex === 0) {
            if (rowSpan[colIndex] > 1) {
                if (b1Border) {
                    result += this.options.chars.left;
                } else {
                    result += " ";
                }
            } else if (b1Border && b2Border) {
                result += this.options.chars.leftMid;
            } else if (b1Border) {
                result += this.options.chars.bottomLeft;
            } else if (b2Border) {
                result += this.options.chars.topLeft;
            } else {
                result += " ";
            }
        } else if (colIndex < opts.columns) {
            if (a1Border && b2Border || b1Border && a2Border) {
                const a1ColSpan = hasColSpan(a1);
                const a2ColSpan = hasColSpan(a2);
                const b1ColSpan = hasColSpan(b1);
                const b2ColSpan = hasColSpan(b2);
                const a1RowSpan = hasRowSpan(a1);
                const a2RowSpan = hasRowSpan(a2);
                const b1RowSpan = hasRowSpan(b1);
                const b2RowSpan = hasRowSpan(b2);
                const hasAllBorder = a1Border && b2Border && b1Border && a2Border;
                const hasAllRowSpan = a1RowSpan && b1RowSpan && a2RowSpan && b2RowSpan;
                const hasAllColSpan = a1ColSpan && b1ColSpan && a2ColSpan && b2ColSpan;
                if (hasAllRowSpan && hasAllBorder) {
                    result += this.options.chars.middle;
                } else if (hasAllColSpan && hasAllBorder && a1 === b1 && a2 === b2) {
                    result += this.options.chars.mid;
                } else if (a1ColSpan && b1ColSpan && a1 === b1) {
                    result += this.options.chars.topMid;
                } else if (a2ColSpan && b2ColSpan && a2 === b2) {
                    result += this.options.chars.bottomMid;
                } else if (a1RowSpan && a2RowSpan && a1 === a2) {
                    result += this.options.chars.leftMid;
                } else if (b1RowSpan && b2RowSpan && b1 === b2) {
                    result += this.options.chars.rightMid;
                } else {
                    result += this.options.chars.midMid;
                }
            } else if (a1Border && b1Border) {
                if (hasColSpan(a1) && hasColSpan(b1) && a1 === b1) {
                    result += this.options.chars.bottom;
                } else {
                    result += this.options.chars.bottomMid;
                }
            } else if (b1Border && b2Border) {
                if (rowSpan[colIndex] > 1) {
                    result += this.options.chars.left;
                } else {
                    result += this.options.chars.leftMid;
                }
            } else if (b2Border && a2Border) {
                if (hasColSpan(a2) && hasColSpan(b2) && a2 === b2) {
                    result += this.options.chars.top;
                } else {
                    result += this.options.chars.topMid;
                }
            } else if (a1Border && a2Border) {
                if (hasRowSpan(a1) && a1 === a2) {
                    result += this.options.chars.right;
                } else {
                    result += this.options.chars.rightMid;
                }
            } else if (a1Border) {
                result += this.options.chars.bottomRight;
            } else if (b1Border) {
                result += this.options.chars.bottomLeft;
            } else if (a2Border) {
                result += this.options.chars.topRight;
            } else if (b2Border) {
                result += this.options.chars.topLeft;
            } else {
                result += " ";
            }
        }
        const length = opts.padding[colIndex] + opts.width[colIndex] + opts.padding[colIndex];
        if (rowSpan[colIndex] > 1 && nextRow) {
            result += this.renderCell(colIndex, nextRow, opts, true);
            if (nextRow[colIndex] === nextRow[nextRow.length - 1]) {
                if (b1Border) {
                    result += this.options.chars.right;
                } else {
                    result += " ";
                }
                return result;
            }
        } else if (b1Border && b2Border) {
            result += this.options.chars.mid.repeat(length);
        } else if (b1Border) {
            result += this.options.chars.bottom.repeat(length);
        } else if (b2Border) {
            result += this.options.chars.top.repeat(length);
        } else {
            result += " ".repeat(length);
        }
        if (colIndex === opts.columns - 1) {
            if (b1Border && b2Border) {
                result += this.options.chars.rightMid;
            } else if (b1Border) {
                result += this.options.chars.bottomRight;
            } else if (b2Border) {
                result += this.options.chars.topRight;
            } else {
                result += " ";
            }
        }
        return result;
    }
}
class Table extends Array {
    static _chars = {
        ...border
    };
    options = {
        indent: 0,
        border: false,
        maxColWidth: Infinity,
        minColWidth: 0,
        padding: 1,
        chars: {
            ...Table._chars
        },
        columns: []
    };
    headerRow;
    static from(rows) {
        const table = new this(...rows);
        if (rows instanceof Table) {
            table.options = {
                ...rows.options
            };
            table.headerRow = rows.headerRow ? Row.from(rows.headerRow) : undefined;
        }
        return table;
    }
    static fromJson(rows) {
        return new this().fromJson(rows);
    }
    static chars(chars) {
        Object.assign(this._chars, chars);
        return this;
    }
    static render(rows) {
        Table.from(rows).render();
    }
    fromJson(rows) {
        this.header(Object.keys(rows[0]));
        this.body(rows.map((row)=>Object.values(row)));
        return this;
    }
    columns(columns) {
        this.options.columns = columns.map((column)=>column instanceof Column ? column : Column.from(column));
        return this;
    }
    column(index, column) {
        if (column instanceof Column) {
            this.options.columns[index] = column;
        } else if (this.options.columns[index]) {
            this.options.columns[index].options(column);
        } else {
            this.options.columns[index] = Column.from(column);
        }
        return this;
    }
    header(header) {
        this.headerRow = header instanceof Row ? header : Row.from(header);
        return this;
    }
    body(rows) {
        this.length = 0;
        this.push(...rows);
        return this;
    }
    clone() {
        const table = new Table(...this.map((row)=>row instanceof Row ? row.clone() : Row.from(row).clone()));
        table.options = {
            ...this.options
        };
        table.headerRow = this.headerRow?.clone();
        return table;
    }
    toString() {
        return new TableLayout(this, this.options).toString();
    }
    render() {
        console.log(this.toString());
        return this;
    }
    maxColWidth(width, override = true) {
        if (override || typeof this.options.maxColWidth === "undefined") {
            this.options.maxColWidth = width;
        }
        return this;
    }
    minColWidth(width, override = true) {
        if (override || typeof this.options.minColWidth === "undefined") {
            this.options.minColWidth = width;
        }
        return this;
    }
    indent(width, override = true) {
        if (override || typeof this.options.indent === "undefined") {
            this.options.indent = width;
        }
        return this;
    }
    padding(padding, override = true) {
        if (override || typeof this.options.padding === "undefined") {
            this.options.padding = padding;
        }
        return this;
    }
    border(enable = true, override = true) {
        if (override || typeof this.options.border === "undefined") {
            this.options.border = enable;
        }
        return this;
    }
    align(direction, override = true) {
        if (override || typeof this.options.align === "undefined") {
            this.options.align = direction;
        }
        return this;
    }
    chars(chars) {
        Object.assign(this.options.chars, chars);
        return this;
    }
    getHeader() {
        return this.headerRow;
    }
    getBody() {
        return [
            ...this
        ];
    }
    getMaxColWidth() {
        return this.options.maxColWidth;
    }
    getMinColWidth() {
        return this.options.minColWidth;
    }
    getIndent() {
        return this.options.indent;
    }
    getPadding() {
        return this.options.padding;
    }
    getBorder() {
        return this.options.border === true;
    }
    hasHeaderBorder() {
        const hasBorder = this.headerRow?.hasBorder();
        return hasBorder === true || this.getBorder() && hasBorder !== false;
    }
    hasBodyBorder() {
        return this.getBorder() || this.options.columns.some((column)=>column.getBorder()) || this.some((row)=>row instanceof Row ? row.hasBorder() : row.some((cell)=>cell instanceof Cell ? cell.getBorder() : false));
    }
    hasBorder() {
        return this.hasHeaderBorder() || this.hasBodyBorder();
    }
    getAlign() {
        return this.options.align ?? "left";
    }
    getColumns() {
        return this.options.columns;
    }
    getColumn(index) {
        return this.options.columns[index] ??= new Column();
    }
}
class HelpGenerator {
    cmd;
    indent;
    options;
    static generate(cmd, options) {
        return new HelpGenerator(cmd, options).generate();
    }
    constructor(cmd, options = {}){
        this.cmd = cmd;
        this.indent = 2;
        this.options = {
            types: false,
            hints: true,
            colors: true,
            long: false,
            ...options
        };
    }
    generate() {
        const areColorsEnabled = getColorEnabled();
        setColorEnabled(this.options.colors);
        const result = this.generateHeader() + this.generateMeta() + this.generateDescription() + this.generateOptions() + this.generateCommands() + this.generateEnvironmentVariables() + this.generateExamples();
        setColorEnabled(areColorsEnabled);
        return result;
    }
    generateHeader() {
        const usage = this.cmd.getUsage();
        const rows = [
            [
                bold("Usage:"),
                brightMagenta(this.cmd.getPath() + (usage ? " " + highlightArguments(usage, this.options.types) : ""))
            ]
        ];
        const version = this.cmd.getVersion();
        if (version) {
            rows.push([
                bold("Version:"),
                yellow(`${this.cmd.getVersion()}`)
            ]);
        }
        return "\n" + Table.from(rows).padding(1).toString() + "\n";
    }
    generateMeta() {
        const meta = Object.entries(this.cmd.getMeta());
        if (!meta.length) {
            return "";
        }
        const rows = [];
        for (const [name, value] of meta){
            rows.push([
                bold(`${name}: `) + value
            ]);
        }
        return "\n" + Table.from(rows).padding(1).toString() + "\n";
    }
    generateDescription() {
        if (!this.cmd.getDescription()) {
            return "";
        }
        return this.label("Description") + Table.from([
            [
                dedent(this.cmd.getDescription())
            ]
        ]).indent(this.indent).maxColWidth(140).padding(1).toString() + "\n";
    }
    generateOptions() {
        const options = this.cmd.getOptions(false);
        if (!options.length) {
            return "";
        }
        let groups = [];
        const hasGroups = options.some((option)=>option.groupName);
        if (hasGroups) {
            for (const option of options){
                let group = groups.find((group)=>group.name === option.groupName);
                if (!group) {
                    group = {
                        name: option.groupName,
                        options: []
                    };
                    groups.push(group);
                }
                group.options.push(option);
            }
        } else {
            groups = [
                {
                    name: "Options",
                    options
                }
            ];
        }
        let result = "";
        for (const group of groups){
            result += this.generateOptionGroup(group);
        }
        return result;
    }
    generateOptionGroup(group) {
        if (!group.options.length) {
            return "";
        }
        const hasTypeDefinitions = !!group.options.find((option)=>!!option.typeDefinition);
        if (hasTypeDefinitions) {
            return this.label(group.name ?? "Options") + Table.from([
                ...group.options.map((option)=>[
                        option.flags.map((flag)=>brightBlue(flag)).join(", "),
                        highlightArguments(option.typeDefinition || "", this.options.types),
                        red(bold("-")),
                        getDescription(option.description, !this.options.long),
                        this.generateHints(option)
                    ])
            ]).padding([
                2,
                2,
                1,
                2
            ]).indent(this.indent).maxColWidth([
                60,
                60,
                1,
                80,
                60
            ]).toString() + "\n";
        }
        return this.label(group.name ?? "Options") + Table.from([
            ...group.options.map((option)=>[
                    option.flags.map((flag)=>brightBlue(flag)).join(", "),
                    red(bold("-")),
                    getDescription(option.description, !this.options.long),
                    this.generateHints(option)
                ])
        ]).indent(this.indent).maxColWidth([
            60,
            1,
            80,
            60
        ]).padding([
            2,
            1,
            2
        ]).toString() + "\n";
    }
    generateCommands() {
        const commands = this.cmd.getCommands(false);
        if (!commands.length) {
            return "";
        }
        const hasTypeDefinitions = !!commands.find((command)=>!!command.getArgsDefinition());
        if (hasTypeDefinitions) {
            return this.label("Commands") + Table.from([
                ...commands.map((command)=>[
                        [
                            command.getName(),
                            ...command.getAliases()
                        ].map((name)=>brightBlue(name)).join(", "),
                        highlightArguments(command.getArgsDefinition() || "", this.options.types),
                        red(bold("-")),
                        command.getShortDescription()
                    ])
            ]).indent(this.indent).maxColWidth([
                60,
                60,
                1,
                80
            ]).padding([
                2,
                2,
                1,
                2
            ]).toString() + "\n";
        }
        return this.label("Commands") + Table.from([
            ...commands.map((command)=>[
                    [
                        command.getName(),
                        ...command.getAliases()
                    ].map((name)=>brightBlue(name)).join(", "),
                    red(bold("-")),
                    command.getShortDescription()
                ])
        ]).maxColWidth([
            60,
            1,
            80
        ]).padding([
            2,
            1,
            2
        ]).indent(this.indent).toString() + "\n";
    }
    generateEnvironmentVariables() {
        const envVars = this.cmd.getEnvVars(false);
        if (!envVars.length) {
            return "";
        }
        return this.label("Environment variables") + Table.from([
            ...envVars.map((envVar)=>[
                    envVar.names.map((name)=>brightBlue(name)).join(", "),
                    highlightArgumentDetails(envVar.details, this.options.types),
                    red(bold("-")),
                    this.options.long ? dedent(envVar.description) : envVar.description.trim().split("\n", 1)[0],
                    envVar.required ? `(${yellow(`required`)})` : ""
                ])
        ]).padding([
            2,
            2,
            1,
            2
        ]).indent(this.indent).maxColWidth([
            60,
            60,
            1,
            80,
            10
        ]).toString() + "\n";
    }
    generateExamples() {
        const examples = this.cmd.getExamples();
        if (!examples.length) {
            return "";
        }
        return this.label("Examples") + Table.from(examples.map((example)=>[
                dim(bold(`${capitalize(example.name)}:`)),
                dedent(example.description)
            ])).padding(1).indent(this.indent).maxColWidth(150).toString() + "\n";
    }
    generateHints(option) {
        if (!this.options.hints) {
            return "";
        }
        const hints = [];
        option.required && hints.push(yellow(`required`));
        if (typeof option.default !== "undefined") {
            const defaultValue = getDefaultValue(option);
            if (typeof defaultValue !== "undefined") {
                hints.push(bold(`Default: `) + inspect(defaultValue, this.options.colors));
            }
        }
        option.depends?.length && hints.push(yellow(bold(`Depends: `)) + italic(option.depends.map(getFlag).join(", ")));
        option.conflicts?.length && hints.push(red(bold(`Conflicts: `)) + italic(option.conflicts.map(getFlag).join(", ")));
        const type = this.cmd.getType(option.args[0]?.type)?.handler;
        if (type instanceof Type) {
            const possibleValues = type.values?.(this.cmd, this.cmd.getParent());
            if (possibleValues?.length) {
                hints.push(bold(`Values: `) + possibleValues.map((value)=>inspect(value, this.options.colors)).join(", "));
            }
        }
        if (hints.length) {
            return `(${hints.join(", ")})`;
        }
        return "";
    }
    label(label) {
        return "\n" + bold(`${label}:`) + "\n\n";
    }
}
function capitalize(string) {
    return (string?.charAt(0).toUpperCase() + string.slice(1)) ?? "";
}
function inspect(value, colors) {
    return Deno.inspect(value, {
        depth: 1,
        colors,
        trailingComma: false
    });
}
function highlightArguments(argsDefinition, types = true) {
    if (!argsDefinition) {
        return "";
    }
    return parseArgumentsDefinition(argsDefinition, false, true).map((arg)=>typeof arg === "string" ? arg : highlightArgumentDetails(arg, types)).join(" ");
}
function highlightArgumentDetails(arg, types = true) {
    let str = "";
    str += yellow(arg.optional ? "[" : "<");
    let name = "";
    name += arg.name;
    if (arg.variadic) {
        name += "...";
    }
    name = brightMagenta(name);
    str += name;
    if (types) {
        str += yellow(":");
        str += red(arg.type);
        if (arg.list) {
            str += green("[]");
        }
    }
    str += yellow(arg.optional ? "]" : ">");
    return str;
}
class Command {
    types = new Map();
    rawArgs = [];
    literalArgs = [];
    _name = "COMMAND";
    _parent;
    _globalParent;
    ver;
    desc = "";
    _usage;
    actionHandler;
    globalActionHandler;
    options = [];
    commands = new Map();
    examples = [];
    envVars = [];
    aliases = [];
    completions = new Map();
    cmd = this;
    argsDefinition;
    isExecutable = false;
    throwOnError = false;
    _allowEmpty = false;
    _stopEarly = false;
    defaultCommand;
    _useRawArgs = false;
    args = [];
    isHidden = false;
    isGlobal = false;
    hasDefaults = false;
    _versionOptions;
    _helpOptions;
    _versionOption;
    _helpOption;
    _help;
    _shouldExit;
    _meta = {};
    _groupName = null;
    _noGlobals = false;
    errorHandler;
    versionOption(flags, desc, opts) {
        this._versionOptions = flags === false ? flags : {
            flags,
            desc,
            opts: typeof opts === "function" ? {
                action: opts
            } : opts
        };
        return this;
    }
    helpOption(flags, desc, opts) {
        this._helpOptions = flags === false ? flags : {
            flags,
            desc,
            opts: typeof opts === "function" ? {
                action: opts
            } : opts
        };
        return this;
    }
    command(nameAndArguments, cmdOrDescription, override) {
        this.reset();
        const result = splitArguments(nameAndArguments);
        const name = result.flags.shift();
        const aliases = result.flags;
        if (!name) {
            throw new MissingCommandNameError();
        }
        if (this.getBaseCommand(name, true)) {
            if (!override) {
                throw new DuplicateCommandNameError(name);
            }
            this.removeCommand(name);
        }
        let description;
        let cmd;
        if (typeof cmdOrDescription === "string") {
            description = cmdOrDescription;
        }
        if (cmdOrDescription instanceof Command) {
            cmd = cmdOrDescription.reset();
        } else {
            cmd = new Command();
        }
        cmd._name = name;
        cmd._parent = this;
        if (description) {
            cmd.description(description);
        }
        if (result.typeDefinition) {
            cmd.arguments(result.typeDefinition);
        }
        aliases.forEach((alias)=>cmd.alias(alias));
        this.commands.set(name, cmd);
        this.select(name);
        return this;
    }
    alias(alias) {
        if (this.cmd._name === alias || this.cmd.aliases.includes(alias)) {
            throw new DuplicateCommandAliasError(alias);
        }
        this.cmd.aliases.push(alias);
        return this;
    }
    reset() {
        this._groupName = null;
        this.cmd = this;
        return this;
    }
    select(name) {
        const cmd = this.getBaseCommand(name, true);
        if (!cmd) {
            throw new CommandNotFoundError(name, this.getBaseCommands(true));
        }
        this.cmd = cmd;
        return this;
    }
    name(name) {
        this.cmd._name = name;
        return this;
    }
    version(version) {
        if (typeof version === "string") {
            this.cmd.ver = ()=>version;
        } else if (typeof version === "function") {
            this.cmd.ver = version;
        }
        return this;
    }
    meta(name, value) {
        this.cmd._meta[name] = value;
        return this;
    }
    getMeta(name) {
        return typeof name === "undefined" ? this._meta : this._meta[name];
    }
    help(help) {
        if (typeof help === "string") {
            this.cmd._help = ()=>help;
        } else if (typeof help === "function") {
            this.cmd._help = help;
        } else {
            this.cmd._help = (cmd, options)=>HelpGenerator.generate(cmd, {
                    ...help,
                    ...options
                });
        }
        return this;
    }
    description(description) {
        this.cmd.desc = description;
        return this;
    }
    usage(usage) {
        this.cmd._usage = usage;
        return this;
    }
    hidden() {
        this.cmd.isHidden = true;
        return this;
    }
    global() {
        this.cmd.isGlobal = true;
        return this;
    }
    executable() {
        this.cmd.isExecutable = true;
        return this;
    }
    arguments(args) {
        this.cmd.argsDefinition = args;
        return this;
    }
    action(fn) {
        this.cmd.actionHandler = fn;
        return this;
    }
    globalAction(fn) {
        this.cmd.globalActionHandler = fn;
        return this;
    }
    allowEmpty(allowEmpty) {
        this.cmd._allowEmpty = allowEmpty !== false;
        return this;
    }
    stopEarly(stopEarly = true) {
        this.cmd._stopEarly = stopEarly;
        return this;
    }
    useRawArgs(useRawArgs = true) {
        this.cmd._useRawArgs = useRawArgs;
        return this;
    }
    default(name) {
        this.cmd.defaultCommand = name;
        return this;
    }
    globalType(name, handler, options) {
        return this.type(name, handler, {
            ...options,
            global: true
        });
    }
    type(name, handler, options) {
        if (this.cmd.types.get(name) && !options?.override) {
            throw new DuplicateTypeError(name);
        }
        this.cmd.types.set(name, {
            ...options,
            name,
            handler: handler
        });
        if (handler instanceof Type && (typeof handler.complete !== "undefined" || typeof handler.values !== "undefined")) {
            const completeHandler = (cmd, parent)=>handler.complete?.(cmd, parent) || [];
            this.complete(name, completeHandler, options);
        }
        return this;
    }
    globalComplete(name, complete, options) {
        return this.complete(name, complete, {
            ...options,
            global: true
        });
    }
    complete(name, complete, options) {
        if (this.cmd.completions.has(name) && !options?.override) {
            throw new DuplicateCompletionError(name);
        }
        this.cmd.completions.set(name, {
            name,
            complete,
            ...options
        });
        return this;
    }
    throwErrors() {
        this.cmd.throwOnError = true;
        return this;
    }
    error(handler) {
        this.cmd.errorHandler = handler;
        return this;
    }
    getErrorHandler() {
        return this.errorHandler ?? this._parent?.errorHandler;
    }
    noExit() {
        this.cmd._shouldExit = false;
        this.throwErrors();
        return this;
    }
    noGlobals() {
        this.cmd._noGlobals = true;
        return this;
    }
    shouldThrowErrors() {
        return this.throwOnError || !!this._parent?.shouldThrowErrors();
    }
    shouldExit() {
        return this._shouldExit ?? this._parent?.shouldExit() ?? true;
    }
    group(name) {
        this.cmd._groupName = name;
        return this;
    }
    globalOption(flags, desc, opts) {
        if (typeof opts === "function") {
            return this.option(flags, desc, {
                value: opts,
                global: true
            });
        }
        return this.option(flags, desc, {
            ...opts,
            global: true
        });
    }
    option(flags, desc, opts) {
        if (typeof opts === "function") {
            opts = {
                value: opts
            };
        }
        const result = splitArguments(flags);
        const args = result.typeDefinition ? parseArgumentsDefinition(result.typeDefinition) : [];
        const option = {
            ...opts,
            name: "",
            description: desc,
            args,
            flags: result.flags,
            equalsSign: result.equalsSign,
            typeDefinition: result.typeDefinition,
            groupName: this._groupName ?? undefined
        };
        if (option.separator) {
            for (const arg of args){
                if (arg.list) {
                    arg.separator = option.separator;
                }
            }
        }
        for (const part of option.flags){
            const arg = part.trim();
            const isLong = /^--/.test(arg);
            const name = isLong ? arg.slice(2) : arg.slice(1);
            if (this.cmd.getBaseOption(name, true)) {
                if (opts?.override) {
                    this.removeOption(name);
                } else {
                    throw new DuplicateOptionNameError(name, this.getPath());
                }
            }
            if (!option.name && isLong) {
                option.name = name;
            } else if (!option.aliases) {
                option.aliases = [
                    name
                ];
            } else {
                option.aliases.push(name);
            }
        }
        if (option.prepend) {
            this.cmd.options.unshift(option);
        } else {
            this.cmd.options.push(option);
        }
        return this;
    }
    example(name, description) {
        if (this.cmd.hasExample(name)) {
            throw new DuplicateExampleError(name);
        }
        this.cmd.examples.push({
            name,
            description
        });
        return this;
    }
    globalEnv(name, description, options) {
        return this.env(name, description, {
            ...options,
            global: true
        });
    }
    env(name, description, options) {
        const result = splitArguments(name);
        if (!result.typeDefinition) {
            result.typeDefinition = "<value:boolean>";
        }
        if (result.flags.some((envName)=>this.cmd.getBaseEnvVar(envName, true))) {
            throw new DuplicateEnvVarError(name);
        }
        const details = parseArgumentsDefinition(result.typeDefinition);
        if (details.length > 1) {
            throw new TooManyEnvVarValuesError(name);
        } else if (details.length && details[0].optional) {
            throw new UnexpectedOptionalEnvVarValueError(name);
        } else if (details.length && details[0].variadic) {
            throw new UnexpectedVariadicEnvVarValueError(name);
        }
        this.cmd.envVars.push({
            name: result.flags[0],
            names: result.flags,
            description,
            type: details[0].type,
            details: details.shift(),
            ...options
        });
        return this;
    }
    parse(args = Deno.args) {
        const ctx = {
            unknown: args.slice(),
            flags: {},
            env: {},
            literal: [],
            stopEarly: false,
            stopOnUnknown: false,
            defaults: {},
            actions: []
        };
        return this.parseCommand(ctx);
    }
    async parseCommand(ctx) {
        try {
            this.reset();
            this.registerDefaults();
            this.rawArgs = ctx.unknown.slice();
            if (this.isExecutable) {
                await this.executeExecutable(ctx.unknown);
                return {
                    options: {},
                    args: [],
                    cmd: this,
                    literal: []
                };
            } else if (this._useRawArgs) {
                await this.parseEnvVars(ctx, this.envVars);
                return await this.execute(ctx.env, ctx.unknown);
            }
            let preParseGlobals = false;
            let subCommand;
            if (ctx.unknown.length > 0) {
                subCommand = this.getSubCommand(ctx);
                if (!subCommand) {
                    const optionName = ctx.unknown[0].replace(/^-+/, "");
                    const option = this.getOption(optionName, true);
                    if (option?.global) {
                        preParseGlobals = true;
                        await this.parseGlobalOptionsAndEnvVars(ctx);
                    }
                }
            }
            if (subCommand || ctx.unknown.length > 0) {
                subCommand ??= this.getSubCommand(ctx);
                if (subCommand) {
                    subCommand._globalParent = this;
                    return subCommand.parseCommand(ctx);
                }
            }
            await this.parseOptionsAndEnvVars(ctx, preParseGlobals);
            const options = {
                ...ctx.env,
                ...ctx.flags
            };
            const args = this.parseArguments(ctx, options);
            this.literalArgs = ctx.literal;
            if (ctx.actions.length) {
                await Promise.all(ctx.actions.map((action)=>action.call(this, options, ...args)));
            }
            if (ctx.standalone) {
                return {
                    options,
                    args,
                    cmd: this,
                    literal: this.literalArgs
                };
            }
            return await this.execute(options, args);
        } catch (error) {
            this.handleError(error);
        }
    }
    getSubCommand(ctx) {
        const subCommand = this.getCommand(ctx.unknown[0], true);
        if (subCommand) {
            ctx.unknown.shift();
        }
        return subCommand;
    }
    async parseGlobalOptionsAndEnvVars(ctx) {
        const isHelpOption = this.getHelpOption()?.flags.includes(ctx.unknown[0]);
        const envVars = [
            ...this.envVars.filter((envVar)=>envVar.global),
            ...this.getGlobalEnvVars(true)
        ];
        await this.parseEnvVars(ctx, envVars, !isHelpOption);
        const options = [
            ...this.options.filter((option)=>option.global),
            ...this.getGlobalOptions(true)
        ];
        this.parseOptions(ctx, options, {
            stopEarly: true,
            stopOnUnknown: true,
            dotted: false
        });
    }
    async parseOptionsAndEnvVars(ctx, preParseGlobals) {
        const helpOption = this.getHelpOption();
        const isVersionOption = this._versionOption?.flags.includes(ctx.unknown[0]);
        const isHelpOption = helpOption && ctx.flags?.[helpOption.name] === true;
        const envVars = preParseGlobals ? this.envVars.filter((envVar)=>!envVar.global) : this.getEnvVars(true);
        await this.parseEnvVars(ctx, envVars, !isHelpOption && !isVersionOption);
        const options = this.getOptions(true);
        this.parseOptions(ctx, options);
    }
    registerDefaults() {
        if (this.hasDefaults || this.getParent()) {
            return this;
        }
        this.hasDefaults = true;
        this.reset();
        !this.types.has("string") && this.type("string", new StringType(), {
            global: true
        });
        !this.types.has("number") && this.type("number", new NumberType(), {
            global: true
        });
        !this.types.has("integer") && this.type("integer", new IntegerType(), {
            global: true
        });
        !this.types.has("boolean") && this.type("boolean", new BooleanType(), {
            global: true
        });
        !this.types.has("file") && this.type("file", new FileType(), {
            global: true
        });
        if (!this._help) {
            this.help({});
        }
        if (this._versionOptions !== false && (this._versionOptions || this.ver)) {
            this.option(this._versionOptions?.flags || "-V, --version", this._versionOptions?.desc || "Show the version number for this program.", {
                standalone: true,
                prepend: true,
                action: async function() {
                    const __long = this.getRawArgs().includes(`--${this._versionOption?.name}`);
                    if (__long) {
                        await checkVersion(this);
                        this.showLongVersion();
                    } else {
                        this.showVersion();
                    }
                    this.exit();
                },
                ...this._versionOptions?.opts ?? {}
            });
            this._versionOption = this.options[0];
        }
        if (this._helpOptions !== false) {
            this.option(this._helpOptions?.flags || "-h, --help", this._helpOptions?.desc || "Show this help.", {
                standalone: true,
                global: true,
                prepend: true,
                action: async function() {
                    const __long = this.getRawArgs().includes(`--${this.getHelpOption()?.name}`);
                    await checkVersion(this);
                    this.showHelp({
                        long: __long
                    });
                    this.exit();
                },
                ...this._helpOptions?.opts ?? {}
            });
            this._helpOption = this.options[0];
        }
        return this;
    }
    async execute(options, args) {
        if (this.defaultCommand) {
            const cmd = this.getCommand(this.defaultCommand, true);
            if (!cmd) {
                throw new DefaultCommandNotFoundError(this.defaultCommand, this.getCommands());
            }
            cmd._globalParent = this;
            return cmd.execute(options, args);
        }
        await this.executeGlobalAction(options, args);
        if (this.actionHandler) {
            await this.actionHandler(options, ...args);
        }
        return {
            options,
            args,
            cmd: this,
            literal: this.literalArgs
        };
    }
    async executeGlobalAction(options, args) {
        if (!this._noGlobals) {
            await this._parent?.executeGlobalAction(options, args);
        }
        await this.globalActionHandler?.(options, ...args);
    }
    async executeExecutable(args) {
        const command = this.getPath().replace(/\s+/g, "-");
        await Deno.permissions.request({
            name: "run",
            command
        });
        try {
            const cmd = new Deno.Command(command, {
                args
            });
            const output = await cmd.output();
            if (!output.success) {
                Deno.exit(output.code);
            }
        } catch (error) {
            if (error instanceof Deno.errors.NotFound) {
                throw new CommandExecutableNotFoundError(command);
            }
            throw error;
        }
    }
    parseOptions(ctx, options, { stopEarly = this._stopEarly, stopOnUnknown = false, dotted = true } = {}) {
        parseFlags(ctx, {
            stopEarly,
            stopOnUnknown,
            dotted,
            allowEmpty: this._allowEmpty,
            flags: options,
            ignoreDefaults: ctx.env,
            parse: (type)=>this.parseType(type),
            option: (option)=>{
                if (option.action) {
                    ctx.actions.push(option.action);
                }
            }
        });
    }
    parseType(type) {
        const typeSettings = this.getType(type.type);
        if (!typeSettings) {
            throw new UnknownTypeError(type.type, this.getTypes().map((type)=>type.name));
        }
        return typeSettings.handler instanceof Type ? typeSettings.handler.parse(type) : typeSettings.handler(type);
    }
    async parseEnvVars(ctx, envVars, validate = true) {
        for (const envVar of envVars){
            const env = await this.findEnvVar(envVar.names);
            if (env) {
                const parseType = (value)=>{
                    return this.parseType({
                        label: "Environment variable",
                        type: envVar.type,
                        name: env.name,
                        value
                    });
                };
                const propertyName = underscoreToCamelCase(envVar.prefix ? envVar.names[0].replace(new RegExp(`^${envVar.prefix}`), "") : envVar.names[0]);
                if (envVar.details.list) {
                    ctx.env[propertyName] = env.value.split(envVar.details.separator ?? ",").map(parseType);
                } else {
                    ctx.env[propertyName] = parseType(env.value);
                }
                if (envVar.value && typeof ctx.env[propertyName] !== "undefined") {
                    ctx.env[propertyName] = envVar.value(ctx.env[propertyName]);
                }
            } else if (envVar.required && validate) {
                throw new MissingRequiredEnvVarError(envVar);
            }
        }
    }
    async findEnvVar(names) {
        for (const name of names){
            const status = await Deno.permissions.query({
                name: "env",
                variable: name
            });
            if (status.state === "granted") {
                const value = Deno.env.get(name);
                if (value) {
                    return {
                        name,
                        value
                    };
                }
            }
        }
        return undefined;
    }
    parseArguments(ctx, options) {
        const params = [];
        const args = ctx.unknown.slice();
        if (!this.hasArguments()) {
            if (args.length) {
                if (this.hasCommands(true)) {
                    if (this.hasCommand(args[0], true)) {
                        throw new TooManyArgumentsError(args);
                    } else {
                        throw new UnknownCommandError(args[0], this.getCommands());
                    }
                } else {
                    throw new NoArgumentsAllowedError(this.getPath());
                }
            }
        } else {
            if (!args.length) {
                const required = this.getArguments().filter((expectedArg)=>!expectedArg.optional).map((expectedArg)=>expectedArg.name);
                if (required.length) {
                    const optionNames = Object.keys(options);
                    const hasStandaloneOption = !!optionNames.find((name)=>this.getOption(name, true)?.standalone);
                    if (!hasStandaloneOption) {
                        throw new MissingArgumentsError(required);
                    }
                }
            } else {
                for (const expectedArg of this.getArguments()){
                    if (!args.length) {
                        if (expectedArg.optional) {
                            break;
                        }
                        throw new MissingArgumentError(expectedArg.name);
                    }
                    let arg;
                    const parseArgValue = (value)=>{
                        return expectedArg.list ? value.split(",").map((value)=>parseArgType(value)) : parseArgType(value);
                    };
                    const parseArgType = (value)=>{
                        return this.parseType({
                            label: "Argument",
                            type: expectedArg.type,
                            name: expectedArg.name,
                            value
                        });
                    };
                    if (expectedArg.variadic) {
                        arg = args.splice(0, args.length).map((value)=>parseArgValue(value));
                    } else {
                        arg = parseArgValue(args.shift());
                    }
                    if (expectedArg.variadic && Array.isArray(arg)) {
                        params.push(...arg);
                    } else if (typeof arg !== "undefined") {
                        params.push(arg);
                    }
                }
                if (args.length) {
                    throw new TooManyArgumentsError(args);
                }
            }
        }
        return params;
    }
    handleError(error) {
        this.throw(error instanceof ValidationError ? new ValidationError1(error.message) : error instanceof Error ? error : new Error(`[non-error-thrown] ${error}`));
    }
    throw(error) {
        if (error instanceof ValidationError1) {
            error.cmd = this;
        }
        this.getErrorHandler()?.(error, this);
        if (this.shouldThrowErrors() || !(error instanceof ValidationError1)) {
            throw error;
        }
        this.showHelp();
        console.error(red(`  ${bold("error")}: ${error.message}\n`));
        Deno.exit(error instanceof ValidationError1 ? error.exitCode : 1);
    }
    getName() {
        return this._name;
    }
    getParent() {
        return this._parent;
    }
    getGlobalParent() {
        return this._globalParent;
    }
    getMainCommand() {
        return this._parent?.getMainCommand() ?? this;
    }
    getAliases() {
        return this.aliases;
    }
    getPath(name) {
        return this._parent ? this._parent.getPath(name) + " " + this._name : name || this._name;
    }
    getArgsDefinition() {
        return this.argsDefinition;
    }
    getArgument(name) {
        return this.getArguments().find((arg)=>arg.name === name);
    }
    getArguments() {
        if (!this.args.length && this.argsDefinition) {
            this.args = parseArgumentsDefinition(this.argsDefinition);
        }
        return this.args;
    }
    hasArguments() {
        return !!this.argsDefinition;
    }
    getVersion() {
        return this.getVersionHandler()?.call(this, this);
    }
    getVersionHandler() {
        return this.ver ?? this._parent?.getVersionHandler();
    }
    getDescription() {
        return typeof this.desc === "function" ? this.desc = this.desc() : this.desc;
    }
    getUsage() {
        return this._usage ?? [
            this.getArgsDefinition(),
            this.getRequiredOptionsDefinition()
        ].join(" ").trim();
    }
    getRequiredOptionsDefinition() {
        return this.getOptions().filter((option)=>option.required).map((option)=>[
                findFlag(option.flags),
                option.typeDefinition
            ].filter((v)=>v).join(" ").trim()).join(" ");
    }
    getShortDescription() {
        return getDescription(this.getDescription(), true);
    }
    getRawArgs() {
        return this.rawArgs;
    }
    getLiteralArgs() {
        return this.literalArgs;
    }
    showVersion() {
        console.log(this.getVersion());
    }
    getLongVersion() {
        return `${bold(this.getMainCommand().getName())} ${brightBlue(this.getVersion() ?? "")}` + Object.entries(this.getMeta()).map(([k, v])=>`\n${bold(k)} ${brightBlue(v)}`).join("");
    }
    showLongVersion() {
        console.log(this.getLongVersion());
    }
    showHelp(options) {
        console.log(this.getHelp(options));
    }
    getHelp(options) {
        this.registerDefaults();
        return this.getHelpHandler().call(this, this, options ?? {});
    }
    getHelpHandler() {
        return this._help ?? this._parent?.getHelpHandler();
    }
    exit(code = 0) {
        if (this.shouldExit()) {
            Deno.exit(code);
        }
    }
    hasOptions(hidden) {
        return this.getOptions(hidden).length > 0;
    }
    getOptions(hidden) {
        return this.getGlobalOptions(hidden).concat(this.getBaseOptions(hidden));
    }
    getBaseOptions(hidden) {
        if (!this.options.length) {
            return [];
        }
        return hidden ? this.options.slice(0) : this.options.filter((opt)=>!opt.hidden);
    }
    getGlobalOptions(hidden) {
        const helpOption = this.getHelpOption();
        const getGlobals = (cmd, noGlobals, options = [], names = [])=>{
            if (cmd.options.length) {
                for (const option of cmd.options){
                    if (option.global && !this.options.find((opt)=>opt.name === option.name) && names.indexOf(option.name) === -1 && (hidden || !option.hidden)) {
                        if (noGlobals && option !== helpOption) {
                            continue;
                        }
                        names.push(option.name);
                        options.push(option);
                    }
                }
            }
            return cmd._parent ? getGlobals(cmd._parent, noGlobals || cmd._noGlobals, options, names) : options;
        };
        return this._parent ? getGlobals(this._parent, this._noGlobals) : [];
    }
    hasOption(name, hidden) {
        return !!this.getOption(name, hidden);
    }
    getOption(name, hidden) {
        return this.getBaseOption(name, hidden) ?? this.getGlobalOption(name, hidden);
    }
    getBaseOption(name, hidden) {
        const option = this.options.find((option)=>option.name === name || option.aliases?.includes(name));
        return option && (hidden || !option.hidden) ? option : undefined;
    }
    getGlobalOption(name, hidden) {
        const helpOption = this.getHelpOption();
        const getGlobalOption = (parent, noGlobals)=>{
            const option = parent.getBaseOption(name, hidden);
            if (!option?.global) {
                return parent._parent && getGlobalOption(parent._parent, noGlobals || parent._noGlobals);
            }
            if (noGlobals && option !== helpOption) {
                return;
            }
            return option;
        };
        return this._parent && getGlobalOption(this._parent, this._noGlobals);
    }
    removeOption(name) {
        const index = this.options.findIndex((option)=>option.name === name);
        if (index === -1) {
            return;
        }
        return this.options.splice(index, 1)[0];
    }
    hasCommands(hidden) {
        return this.getCommands(hidden).length > 0;
    }
    getCommands(hidden) {
        return this.getGlobalCommands(hidden).concat(this.getBaseCommands(hidden));
    }
    getBaseCommands(hidden) {
        const commands = Array.from(this.commands.values());
        return hidden ? commands : commands.filter((cmd)=>!cmd.isHidden);
    }
    getGlobalCommands(hidden) {
        const getCommands = (command, noGlobals, commands = [], names = [])=>{
            if (command.commands.size) {
                for (const [_, cmd] of command.commands){
                    if (cmd.isGlobal && this !== cmd && !this.commands.has(cmd._name) && names.indexOf(cmd._name) === -1 && (hidden || !cmd.isHidden)) {
                        if (noGlobals && cmd?.getName() !== "help") {
                            continue;
                        }
                        names.push(cmd._name);
                        commands.push(cmd);
                    }
                }
            }
            return command._parent ? getCommands(command._parent, noGlobals || command._noGlobals, commands, names) : commands;
        };
        return this._parent ? getCommands(this._parent, this._noGlobals) : [];
    }
    hasCommand(name, hidden) {
        return !!this.getCommand(name, hidden);
    }
    getCommand(name, hidden) {
        return this.getBaseCommand(name, hidden) ?? this.getGlobalCommand(name, hidden);
    }
    getBaseCommand(name, hidden) {
        for (const cmd of this.commands.values()){
            if (cmd._name === name || cmd.aliases.includes(name)) {
                return cmd && (hidden || !cmd.isHidden) ? cmd : undefined;
            }
        }
    }
    getGlobalCommand(name, hidden) {
        const getGlobalCommand = (parent, noGlobals)=>{
            const cmd = parent.getBaseCommand(name, hidden);
            if (!cmd?.isGlobal) {
                return parent._parent && getGlobalCommand(parent._parent, noGlobals || parent._noGlobals);
            }
            if (noGlobals && cmd.getName() !== "help") {
                return;
            }
            return cmd;
        };
        return this._parent && getGlobalCommand(this._parent, this._noGlobals);
    }
    removeCommand(name) {
        const command = this.getBaseCommand(name, true);
        if (command) {
            this.commands.delete(command._name);
        }
        return command;
    }
    getTypes() {
        return this.getGlobalTypes().concat(this.getBaseTypes());
    }
    getBaseTypes() {
        return Array.from(this.types.values());
    }
    getGlobalTypes() {
        const getTypes = (cmd, types = [], names = [])=>{
            if (cmd) {
                if (cmd.types.size) {
                    cmd.types.forEach((type)=>{
                        if (type.global && !this.types.has(type.name) && names.indexOf(type.name) === -1) {
                            names.push(type.name);
                            types.push(type);
                        }
                    });
                }
                return getTypes(cmd._parent, types, names);
            }
            return types;
        };
        return getTypes(this._parent);
    }
    getType(name) {
        return this.getBaseType(name) ?? this.getGlobalType(name);
    }
    getBaseType(name) {
        return this.types.get(name);
    }
    getGlobalType(name) {
        if (!this._parent) {
            return;
        }
        const cmd = this._parent.getBaseType(name);
        if (!cmd?.global) {
            return this._parent.getGlobalType(name);
        }
        return cmd;
    }
    getCompletions() {
        return this.getGlobalCompletions().concat(this.getBaseCompletions());
    }
    getBaseCompletions() {
        return Array.from(this.completions.values());
    }
    getGlobalCompletions() {
        const getCompletions = (cmd, completions = [], names = [])=>{
            if (cmd) {
                if (cmd.completions.size) {
                    cmd.completions.forEach((completion)=>{
                        if (completion.global && !this.completions.has(completion.name) && names.indexOf(completion.name) === -1) {
                            names.push(completion.name);
                            completions.push(completion);
                        }
                    });
                }
                return getCompletions(cmd._parent, completions, names);
            }
            return completions;
        };
        return getCompletions(this._parent);
    }
    getCompletion(name) {
        return this.getBaseCompletion(name) ?? this.getGlobalCompletion(name);
    }
    getBaseCompletion(name) {
        return this.completions.get(name);
    }
    getGlobalCompletion(name) {
        if (!this._parent) {
            return;
        }
        const completion = this._parent.getBaseCompletion(name);
        if (!completion?.global) {
            return this._parent.getGlobalCompletion(name);
        }
        return completion;
    }
    hasEnvVars(hidden) {
        return this.getEnvVars(hidden).length > 0;
    }
    getEnvVars(hidden) {
        return this.getGlobalEnvVars(hidden).concat(this.getBaseEnvVars(hidden));
    }
    getBaseEnvVars(hidden) {
        if (!this.envVars.length) {
            return [];
        }
        return hidden ? this.envVars.slice(0) : this.envVars.filter((env)=>!env.hidden);
    }
    getGlobalEnvVars(hidden) {
        if (this._noGlobals) {
            return [];
        }
        const getEnvVars = (cmd, envVars = [], names = [])=>{
            if (cmd) {
                if (cmd.envVars.length) {
                    cmd.envVars.forEach((envVar)=>{
                        if (envVar.global && !this.envVars.find((env)=>env.names[0] === envVar.names[0]) && names.indexOf(envVar.names[0]) === -1 && (hidden || !envVar.hidden)) {
                            names.push(envVar.names[0]);
                            envVars.push(envVar);
                        }
                    });
                }
                return getEnvVars(cmd._parent, envVars, names);
            }
            return envVars;
        };
        return getEnvVars(this._parent);
    }
    hasEnvVar(name, hidden) {
        return !!this.getEnvVar(name, hidden);
    }
    getEnvVar(name, hidden) {
        return this.getBaseEnvVar(name, hidden) ?? this.getGlobalEnvVar(name, hidden);
    }
    getBaseEnvVar(name, hidden) {
        const envVar = this.envVars.find((env)=>env.names.indexOf(name) !== -1);
        return envVar && (hidden || !envVar.hidden) ? envVar : undefined;
    }
    getGlobalEnvVar(name, hidden) {
        if (!this._parent || this._noGlobals) {
            return;
        }
        const envVar = this._parent.getBaseEnvVar(name, hidden);
        if (!envVar?.global) {
            return this._parent.getGlobalEnvVar(name, hidden);
        }
        return envVar;
    }
    hasExamples() {
        return this.examples.length > 0;
    }
    getExamples() {
        return this.examples;
    }
    hasExample(name) {
        return !!this.getExample(name);
    }
    getExample(name) {
        return this.examples.find((example)=>example.name === name);
    }
    getHelpOption() {
        return this._helpOption ?? this._parent?.getHelpOption();
    }
}
async function checkVersion(cmd) {
    const mainCommand = cmd.getMainCommand();
    const upgradeCommand = mainCommand.getCommand("upgrade");
    if (!isUpgradeCommand(upgradeCommand)) {
        return;
    }
    const latestVersion = await upgradeCommand.getLatestVersion();
    const currentVersion = mainCommand.getVersion();
    if (currentVersion === latestVersion) {
        return;
    }
    const versionHelpText = `(New version available: ${latestVersion}. Run '${mainCommand.getName()} upgrade' to upgrade to the latest version!)`;
    mainCommand.version(`${currentVersion}  ${bold(yellow(versionHelpText))}`);
}
function findFlag(flags) {
    for (const flag of flags){
        if (flag.startsWith("--")) {
            return flag;
        }
    }
    return flags[0];
}
function isUpgradeCommand(command) {
    return command instanceof Command && "getLatestVersion" in command;
}
class HttpServer1 {
    spacePrimitives;
    options;
    app;
    abortController;
    constructor(spacePrimitives, options){
        this.spacePrimitives = spacePrimitives;
        this.options = options;
        this.app = new Application();
    }
    start() {
        const fsRouter = this.addFsRoutes();
        this.app.use(fsRouter.routes());
        this.app.use(fsRouter.allowedMethods());
        this.abortController = new AbortController();
        const listenOptions = {
            hostname: this.options.hostname,
            port: this.options.port,
            signal: this.abortController.signal
        };
        this.app.listen(listenOptions).catch((e)=>{
            console.log("Server listen error:", e.message);
            Deno.exit(1);
        });
        const visibleHostname = this.options.hostname === "0.0.0.0" ? "localhost" : this.options.hostname;
        console.log(`SilverBullet Pub server is now running: http://${visibleHostname}:${this.options.port}`);
    }
    addFsRoutes() {
        const fsRouter = new Router();
        const corsMiddleware = oakCors({
            allowedHeaders: "*",
            exposedHeaders: "*",
            methods: [
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "HEAD",
                "OPTIONS"
            ]
        });
        fsRouter.use(corsMiddleware);
        fsRouter.get("/index.json", async ({ response })=>{
            response.headers.set("Content-type", "application/json");
            response.headers.set("X-Space-Path", this.options.pagesPath);
            const files = await this.spacePrimitives.fetchFileList();
            files.forEach((f)=>{
                f.perm = "ro";
            });
            response.body = JSON.stringify(files);
        });
        const filePathRegex = "\/(.*)";
        fsRouter.get(filePathRegex, async ({ params, response, request })=>{
            let name = params[0];
            if (name === "") {
                name = "index.html";
            }
            console.log("Requested file", name);
            if (name.startsWith(".")) {
                response.status = 404;
                response.body = "Not exposed";
                return;
            }
            try {
                if (request.headers.has("X-Get-Meta")) {
                    const fileData = await this.spacePrimitives.getFileMeta(name);
                    response.status = 200;
                    this.fileMetaToHeaders(response.headers, fileData);
                    response.body = "";
                    return;
                }
                let fileData;
                try {
                    fileData = await this.spacePrimitives.readFile(name);
                } catch (e) {
                    if (e.message === "Not found") {
                        fileData = await this.spacePrimitives.readFile(`${name}/index.html`);
                    }
                }
                if (!fileData) {
                    response.status = 404;
                    response.body = "Not found";
                    return;
                }
                const lastModifiedHeader = new Date(fileData.meta.lastModified).toUTCString();
                if (request.headers.get("If-Modified-Since") === lastModifiedHeader) {
                    response.status = 304;
                    return;
                }
                response.status = 200;
                this.fileMetaToHeaders(response.headers, fileData.meta);
                response.headers.set("Last-Modified", lastModifiedHeader);
                response.body = fileData.data;
            } catch (e) {
                console.error("Error GETting file", name, e.message);
                response.status = 404;
                response.body = "Not found";
            }
        }).put(filePathRegex, async ({ request, response, params })=>{
            const name = params[0];
            if (!this.ensureAuth(request, response)) {
                return;
            }
            console.log("Saving file", name);
            if (name.startsWith(".")) {
                response.status = 403;
                return;
            }
            const body = await request.body({
                type: "bytes"
            }).value;
            try {
                const meta = await this.spacePrimitives.writeFile(name, body);
                response.status = 200;
                this.fileMetaToHeaders(response.headers, meta);
                response.body = "OK";
            } catch (err) {
                console.error("Write failed", err);
                response.status = 500;
                response.body = "Write failed";
            }
        }).delete(filePathRegex, async ({ request, response, params })=>{
            if (!this.ensureAuth(request, response)) {
                return;
            }
            const name = params[0];
            if (name === "index.json") {
                response.status = 200;
                response.body = "OK (noop)";
                return;
            }
            console.log("Deleting file", name);
            if (name.startsWith(".")) {
                response.status = 403;
                return;
            }
            try {
                await this.spacePrimitives.deleteFile(name);
                response.status = 200;
                response.body = "OK";
            } catch (e) {
                console.error("Error deleting attachment", e);
                response.status = 500;
                response.body = e.message;
            }
        }).options(filePathRegex, corsMiddleware);
        return fsRouter;
    }
    ensureAuth(request, response) {
        const authHeader = request.headers.get("Authorization");
        if (!authHeader) {
            response.status = 401;
            response.body = "No Authorization header";
            return false;
        }
        const token = authHeader.split(" ")[1];
        if (token !== this.options.token) {
            response.status = 401;
            response.body = "Invalid token";
            return false;
        }
        return true;
    }
    fileMetaToHeaders(headers, fileMeta) {
        headers.set("Content-Type", fileMeta.contentType);
        headers.set("X-Last-Modified", "" + fileMeta.lastModified);
        headers.set("Cache-Control", "no-cache");
        headers.set("X-Permission", "ro");
        headers.set("X-Created", "" + fileMeta.created);
        headers.set("X-Content-Length", "" + fileMeta.size);
    }
    stop() {
        if (this.abortController) {
            this.abortController.abort();
            console.log("stopped server");
        }
    }
}
const osType1 = (()=>{
    const { Deno: Deno1 } = globalThis;
    if (typeof Deno1?.build?.os === "string") {
        return Deno1.build.os;
    }
    const { navigator } = globalThis;
    if (navigator?.appVersion?.includes?.("Win")) {
        return "windows";
    }
    return "linux";
})();
const isWindows1 = osType1 === "windows";
const CHAR_FORWARD_SLASH1 = 47;
function assertPath1(path) {
    if (typeof path !== "string") {
        throw new TypeError(`Path must be a string. Received ${JSON.stringify(path)}`);
    }
}
function isPosixPathSeparator1(code) {
    return code === 47;
}
function isPathSeparator1(code) {
    return isPosixPathSeparator1(code) || code === 92;
}
function isWindowsDeviceRoot1(code) {
    return code >= 97 && code <= 122 || code >= 65 && code <= 90;
}
function normalizeString1(path, allowAboveRoot, separator, isPathSeparator) {
    let res = "";
    let lastSegmentLength = 0;
    let lastSlash = -1;
    let dots = 0;
    let code;
    for(let i = 0, len = path.length; i <= len; ++i){
        if (i < len) code = path.charCodeAt(i);
        else if (isPathSeparator(code)) break;
        else code = CHAR_FORWARD_SLASH1;
        if (isPathSeparator(code)) {
            if (lastSlash === i - 1 || dots === 1) {} else if (lastSlash !== i - 1 && dots === 2) {
                if (res.length < 2 || lastSegmentLength !== 2 || res.charCodeAt(res.length - 1) !== 46 || res.charCodeAt(res.length - 2) !== 46) {
                    if (res.length > 2) {
                        const lastSlashIndex = res.lastIndexOf(separator);
                        if (lastSlashIndex === -1) {
                            res = "";
                            lastSegmentLength = 0;
                        } else {
                            res = res.slice(0, lastSlashIndex);
                            lastSegmentLength = res.length - 1 - res.lastIndexOf(separator);
                        }
                        lastSlash = i;
                        dots = 0;
                        continue;
                    } else if (res.length === 2 || res.length === 1) {
                        res = "";
                        lastSegmentLength = 0;
                        lastSlash = i;
                        dots = 0;
                        continue;
                    }
                }
                if (allowAboveRoot) {
                    if (res.length > 0) res += `${separator}..`;
                    else res = "..";
                    lastSegmentLength = 2;
                }
            } else {
                if (res.length > 0) res += separator + path.slice(lastSlash + 1, i);
                else res = path.slice(lastSlash + 1, i);
                lastSegmentLength = i - lastSlash - 1;
            }
            lastSlash = i;
            dots = 0;
        } else if (code === 46 && dots !== -1) {
            ++dots;
        } else {
            dots = -1;
        }
    }
    return res;
}
function _format1(sep, pathObject) {
    const dir = pathObject.dir || pathObject.root;
    const base = pathObject.base || (pathObject.name || "") + (pathObject.ext || "");
    if (!dir) return base;
    if (base === sep) return dir;
    if (dir === pathObject.root) return dir + base;
    return dir + sep + base;
}
const WHITESPACE_ENCODINGS1 = {
    "\u0009": "%09",
    "\u000A": "%0A",
    "\u000B": "%0B",
    "\u000C": "%0C",
    "\u000D": "%0D",
    "\u0020": "%20"
};
function encodeWhitespace1(string) {
    return string.replaceAll(/[\s]/g, (c)=>{
        return WHITESPACE_ENCODINGS1[c] ?? c;
    });
}
function lastPathSegment1(path, isSep, start = 0) {
    let matchedNonSeparator = false;
    let end = path.length;
    for(let i = path.length - 1; i >= start; --i){
        if (isSep(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                start = i + 1;
                break;
            }
        } else if (!matchedNonSeparator) {
            matchedNonSeparator = true;
            end = i + 1;
        }
    }
    return path.slice(start, end);
}
function stripTrailingSeparators1(segment, isSep) {
    if (segment.length <= 1) {
        return segment;
    }
    let end = segment.length;
    for(let i = segment.length - 1; i > 0; i--){
        if (isSep(segment.charCodeAt(i))) {
            end = i;
        } else {
            break;
        }
    }
    return segment.slice(0, end);
}
function stripSuffix1(name, suffix) {
    if (suffix.length >= name.length) {
        return name;
    }
    const lenDiff = name.length - suffix.length;
    for(let i = suffix.length - 1; i >= 0; --i){
        if (name.charCodeAt(lenDiff + i) !== suffix.charCodeAt(i)) {
            return name;
        }
    }
    return name.slice(0, -suffix.length);
}
class DenoStdInternalError1 extends Error {
    constructor(message){
        super(message);
        this.name = "DenoStdInternalError";
    }
}
function assert2(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError1(msg);
    }
}
const sep3 = "\\";
const delimiter3 = ";";
function resolve3(...pathSegments) {
    let resolvedDevice = "";
    let resolvedTail = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1; i--){
        let path;
        const { Deno: Deno1 } = globalThis;
        if (i >= 0) {
            path = pathSegments[i];
        } else if (!resolvedDevice) {
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a drive-letter-less path without a CWD.");
            }
            path = Deno1.cwd();
        } else {
            if (typeof Deno1?.env?.get !== "function" || typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
            if (path === undefined || path.slice(0, 3).toLowerCase() !== `${resolvedDevice.toLowerCase()}\\`) {
                path = `${resolvedDevice}\\`;
            }
        }
        assertPath1(path);
        const len = path.length;
        if (len === 0) continue;
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator1(code)) {
                isAbsolute = true;
                if (isPathSeparator1(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        const firstPart = path.slice(last, j);
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator1(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator1(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                device = `\\\\${firstPart}\\${path.slice(last)}`;
                                rootEnd = j;
                            } else if (j !== last) {
                                device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                                rootEnd = j;
                            }
                        }
                    }
                } else {
                    rootEnd = 1;
                }
            } else if (isWindowsDeviceRoot1(code)) {
                if (path.charCodeAt(1) === 58) {
                    device = path.slice(0, 2);
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator1(path.charCodeAt(2))) {
                            isAbsolute = true;
                            rootEnd = 3;
                        }
                    }
                }
            }
        } else if (isPathSeparator1(code)) {
            rootEnd = 1;
            isAbsolute = true;
        }
        if (device.length > 0 && resolvedDevice.length > 0 && device.toLowerCase() !== resolvedDevice.toLowerCase()) {
            continue;
        }
        if (resolvedDevice.length === 0 && device.length > 0) {
            resolvedDevice = device;
        }
        if (!resolvedAbsolute) {
            resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
            resolvedAbsolute = isAbsolute;
        }
        if (resolvedAbsolute && resolvedDevice.length > 0) break;
    }
    resolvedTail = normalizeString1(resolvedTail, !resolvedAbsolute, "\\", isPathSeparator1);
    return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail || ".";
}
function normalize5(path) {
    assertPath1(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = 0;
    let device;
    let isAbsolute = false;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator1(code)) {
            isAbsolute = true;
            if (isPathSeparator1(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator1(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    const firstPart = path.slice(last, j);
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator1(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return `\\\\${firstPart}\\${path.slice(last)}\\`;
                        } else if (j !== last) {
                            device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                            rootEnd = j;
                        }
                    }
                }
            } else {
                rootEnd = 1;
            }
        } else if (isWindowsDeviceRoot1(code)) {
            if (path.charCodeAt(1) === 58) {
                device = path.slice(0, 2);
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator1(path.charCodeAt(2))) {
                        isAbsolute = true;
                        rootEnd = 3;
                    }
                }
            }
        }
    } else if (isPathSeparator1(code)) {
        return "\\";
    }
    let tail;
    if (rootEnd < len) {
        tail = normalizeString1(path.slice(rootEnd), !isAbsolute, "\\", isPathSeparator1);
    } else {
        tail = "";
    }
    if (tail.length === 0 && !isAbsolute) tail = ".";
    if (tail.length > 0 && isPathSeparator1(path.charCodeAt(len - 1))) {
        tail += "\\";
    }
    if (device === undefined) {
        if (isAbsolute) {
            if (tail.length > 0) return `\\${tail}`;
            else return "\\";
        } else if (tail.length > 0) {
            return tail;
        } else {
            return "";
        }
    } else if (isAbsolute) {
        if (tail.length > 0) return `${device}\\${tail}`;
        else return `${device}\\`;
    } else if (tail.length > 0) {
        return device + tail;
    } else {
        return device;
    }
}
function isAbsolute3(path) {
    assertPath1(path);
    const len = path.length;
    if (len === 0) return false;
    const code = path.charCodeAt(0);
    if (isPathSeparator1(code)) {
        return true;
    } else if (isWindowsDeviceRoot1(code)) {
        if (len > 2 && path.charCodeAt(1) === 58) {
            if (isPathSeparator1(path.charCodeAt(2))) return true;
        }
    }
    return false;
}
function join4(...paths) {
    const pathsCount = paths.length;
    if (pathsCount === 0) return ".";
    let joined;
    let firstPart = null;
    for(let i = 0; i < pathsCount; ++i){
        const path = paths[i];
        assertPath1(path);
        if (path.length > 0) {
            if (joined === undefined) joined = firstPart = path;
            else joined += `\\${path}`;
        }
    }
    if (joined === undefined) return ".";
    let needsReplace = true;
    let slashCount = 0;
    assert2(firstPart != null);
    if (isPathSeparator1(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
            if (isPathSeparator1(firstPart.charCodeAt(1))) {
                ++slashCount;
                if (firstLen > 2) {
                    if (isPathSeparator1(firstPart.charCodeAt(2))) ++slashCount;
                    else {
                        needsReplace = false;
                    }
                }
            }
        }
    }
    if (needsReplace) {
        for(; slashCount < joined.length; ++slashCount){
            if (!isPathSeparator1(joined.charCodeAt(slashCount))) break;
        }
        if (slashCount >= 2) joined = `\\${joined.slice(slashCount)}`;
    }
    return normalize5(joined);
}
function relative3(from, to) {
    assertPath1(from);
    assertPath1(to);
    if (from === to) return "";
    const fromOrig = resolve3(from);
    const toOrig = resolve3(to);
    if (fromOrig === toOrig) return "";
    from = fromOrig.toLowerCase();
    to = toOrig.toLowerCase();
    if (from === to) return "";
    let fromStart = 0;
    let fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (from.charCodeAt(fromStart) !== 92) break;
    }
    for(; fromEnd - 1 > fromStart; --fromEnd){
        if (from.charCodeAt(fromEnd - 1) !== 92) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 0;
    let toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (to.charCodeAt(toStart) !== 92) break;
    }
    for(; toEnd - 1 > toStart; --toEnd){
        if (to.charCodeAt(toEnd - 1) !== 92) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (to.charCodeAt(toStart + i) === 92) {
                    return toOrig.slice(toStart + i + 1);
                } else if (i === 2) {
                    return toOrig.slice(toStart + i);
                }
            }
            if (fromLen > length) {
                if (from.charCodeAt(fromStart + i) === 92) {
                    lastCommonSep = i;
                } else if (i === 2) {
                    lastCommonSep = 3;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (fromCode === 92) lastCommonSep = i;
    }
    if (i !== length && lastCommonSep === -1) {
        return toOrig;
    }
    let out = "";
    if (lastCommonSep === -1) lastCommonSep = 0;
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || from.charCodeAt(i) === 92) {
            if (out.length === 0) out += "..";
            else out += "\\..";
        }
    }
    if (out.length > 0) {
        return out + toOrig.slice(toStart + lastCommonSep, toEnd);
    } else {
        toStart += lastCommonSep;
        if (toOrig.charCodeAt(toStart) === 92) ++toStart;
        return toOrig.slice(toStart, toEnd);
    }
}
function toNamespacedPath3(path) {
    if (typeof path !== "string") return path;
    if (path.length === 0) return "";
    const resolvedPath = resolve3(path);
    if (resolvedPath.length >= 3) {
        if (resolvedPath.charCodeAt(0) === 92) {
            if (resolvedPath.charCodeAt(1) === 92) {
                const code = resolvedPath.charCodeAt(2);
                if (code !== 63 && code !== 46) {
                    return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
                }
            }
        } else if (isWindowsDeviceRoot1(resolvedPath.charCodeAt(0))) {
            if (resolvedPath.charCodeAt(1) === 58 && resolvedPath.charCodeAt(2) === 92) {
                return `\\\\?\\${resolvedPath}`;
            }
        }
    }
    return path;
}
function dirname3(path) {
    assertPath1(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = -1;
    let end = -1;
    let matchedSlash = true;
    let offset = 0;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator1(code)) {
            rootEnd = offset = 1;
            if (isPathSeparator1(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator1(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator1(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return path;
                        }
                        if (j !== last) {
                            rootEnd = offset = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot1(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = offset = 2;
                if (len > 2) {
                    if (isPathSeparator1(path.charCodeAt(2))) rootEnd = offset = 3;
                }
            }
        }
    } else if (isPathSeparator1(code)) {
        return path;
    }
    for(let i = len - 1; i >= offset; --i){
        if (isPathSeparator1(path.charCodeAt(i))) {
            if (!matchedSlash) {
                end = i;
                break;
            }
        } else {
            matchedSlash = false;
        }
    }
    if (end === -1) {
        if (rootEnd === -1) return ".";
        else end = rootEnd;
    }
    return stripTrailingSeparators1(path.slice(0, end), isPosixPathSeparator1);
}
function basename3(path, suffix = "") {
    assertPath1(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
    let start = 0;
    if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (isWindowsDeviceRoot1(drive)) {
            if (path.charCodeAt(1) === 58) start = 2;
        }
    }
    const lastSegment = lastPathSegment1(path, isPathSeparator1, start);
    const strippedSegment = stripTrailingSeparators1(lastSegment, isPathSeparator1);
    return suffix ? stripSuffix1(strippedSegment, suffix) : strippedSegment;
}
function extname3(path) {
    assertPath1(path);
    let start = 0;
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    if (path.length >= 2 && path.charCodeAt(1) === 58 && isWindowsDeviceRoot1(path.charCodeAt(0))) {
        start = startPart = 2;
    }
    for(let i = path.length - 1; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPathSeparator1(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format4(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format1("\\", pathObject);
}
function parse5(path) {
    assertPath1(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    const len = path.length;
    if (len === 0) return ret;
    let rootEnd = 0;
    let code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator1(code)) {
            rootEnd = 1;
            if (isPathSeparator1(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator1(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator1(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            rootEnd = j;
                        } else if (j !== last) {
                            rootEnd = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot1(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator1(path.charCodeAt(2))) {
                        if (len === 3) {
                            ret.root = ret.dir = path;
                            ret.base = "\\";
                            return ret;
                        }
                        rootEnd = 3;
                    }
                } else {
                    ret.root = ret.dir = path;
                    return ret;
                }
            }
        }
    } else if (isPathSeparator1(code)) {
        ret.root = ret.dir = path;
        ret.base = "\\";
        return ret;
    }
    if (rootEnd > 0) ret.root = path.slice(0, rootEnd);
    let startDot = -1;
    let startPart = rootEnd;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= rootEnd; --i){
        code = path.charCodeAt(i);
        if (isPathSeparator1(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            ret.base = ret.name = path.slice(startPart, end);
        }
    } else {
        ret.name = path.slice(startPart, startDot);
        ret.base = path.slice(startPart, end);
        ret.ext = path.slice(startDot, end);
    }
    ret.base = ret.base || "\\";
    if (startPart > 0 && startPart !== rootEnd) {
        ret.dir = path.slice(0, startPart - 1);
    } else ret.dir = ret.root;
    return ret;
}
function fromFileUrl3(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    let path = decodeURIComponent(url.pathname.replace(/\//g, "\\").replace(/%(?![0-9A-Fa-f]{2})/g, "%25")).replace(/^\\*([A-Za-z]:)(\\|$)/, "$1\\");
    if (url.hostname != "") {
        path = `\\\\${url.hostname}${path}`;
    }
    return path;
}
function toFileUrl3(path) {
    if (!isAbsolute3(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const [, hostname, pathname] = path.match(/^(?:[/\\]{2}([^/\\]+)(?=[/\\](?:[^/\\]|$)))?(.*)/);
    const url = new URL("file:///");
    url.pathname = encodeWhitespace1(pathname.replace(/%/g, "%25"));
    if (hostname != null && hostname != "localhost") {
        url.hostname = hostname;
        if (!url.hostname) {
            throw new TypeError("Invalid hostname.");
        }
    }
    return url;
}
const mod2 = {
    sep: sep3,
    delimiter: delimiter3,
    resolve: resolve3,
    normalize: normalize5,
    isAbsolute: isAbsolute3,
    join: join4,
    relative: relative3,
    toNamespacedPath: toNamespacedPath3,
    dirname: dirname3,
    basename: basename3,
    extname: extname3,
    format: format4,
    parse: parse5,
    fromFileUrl: fromFileUrl3,
    toFileUrl: toFileUrl3
};
const sep4 = "/";
const delimiter4 = ":";
function resolve4(...pathSegments) {
    let resolvedPath = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1 && !resolvedAbsolute; i--){
        let path;
        if (i >= 0) path = pathSegments[i];
        else {
            const { Deno: Deno1 } = globalThis;
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
        }
        assertPath1(path);
        if (path.length === 0) {
            continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute = isPosixPathSeparator1(path.charCodeAt(0));
    }
    resolvedPath = normalizeString1(resolvedPath, !resolvedAbsolute, "/", isPosixPathSeparator1);
    if (resolvedAbsolute) {
        if (resolvedPath.length > 0) return `/${resolvedPath}`;
        else return "/";
    } else if (resolvedPath.length > 0) return resolvedPath;
    else return ".";
}
function normalize6(path) {
    assertPath1(path);
    if (path.length === 0) return ".";
    const isAbsolute = isPosixPathSeparator1(path.charCodeAt(0));
    const trailingSeparator = isPosixPathSeparator1(path.charCodeAt(path.length - 1));
    path = normalizeString1(path, !isAbsolute, "/", isPosixPathSeparator1);
    if (path.length === 0 && !isAbsolute) path = ".";
    if (path.length > 0 && trailingSeparator) path += "/";
    if (isAbsolute) return `/${path}`;
    return path;
}
function isAbsolute4(path) {
    assertPath1(path);
    return path.length > 0 && isPosixPathSeparator1(path.charCodeAt(0));
}
function join5(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    for(let i = 0, len = paths.length; i < len; ++i){
        const path = paths[i];
        assertPath1(path);
        if (path.length > 0) {
            if (!joined) joined = path;
            else joined += `/${path}`;
        }
    }
    if (!joined) return ".";
    return normalize6(joined);
}
function relative4(from, to) {
    assertPath1(from);
    assertPath1(to);
    if (from === to) return "";
    from = resolve4(from);
    to = resolve4(to);
    if (from === to) return "";
    let fromStart = 1;
    const fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (!isPosixPathSeparator1(from.charCodeAt(fromStart))) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 1;
    const toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (!isPosixPathSeparator1(to.charCodeAt(toStart))) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (isPosixPathSeparator1(to.charCodeAt(toStart + i))) {
                    return to.slice(toStart + i + 1);
                } else if (i === 0) {
                    return to.slice(toStart + i);
                }
            } else if (fromLen > length) {
                if (isPosixPathSeparator1(from.charCodeAt(fromStart + i))) {
                    lastCommonSep = i;
                } else if (i === 0) {
                    lastCommonSep = 0;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (isPosixPathSeparator1(fromCode)) lastCommonSep = i;
    }
    let out = "";
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || isPosixPathSeparator1(from.charCodeAt(i))) {
            if (out.length === 0) out += "..";
            else out += "/..";
        }
    }
    if (out.length > 0) return out + to.slice(toStart + lastCommonSep);
    else {
        toStart += lastCommonSep;
        if (isPosixPathSeparator1(to.charCodeAt(toStart))) ++toStart;
        return to.slice(toStart);
    }
}
function toNamespacedPath4(path) {
    return path;
}
function dirname4(path) {
    if (path.length === 0) return ".";
    let end = -1;
    let matchedNonSeparator = false;
    for(let i = path.length - 1; i >= 1; --i){
        if (isPosixPathSeparator1(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                end = i;
                break;
            }
        } else {
            matchedNonSeparator = true;
        }
    }
    if (end === -1) {
        return isPosixPathSeparator1(path.charCodeAt(0)) ? "/" : ".";
    }
    return stripTrailingSeparators1(path.slice(0, end), isPosixPathSeparator1);
}
function basename4(path, suffix = "") {
    assertPath1(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
    const lastSegment = lastPathSegment1(path, isPosixPathSeparator1);
    const strippedSegment = stripTrailingSeparators1(lastSegment, isPosixPathSeparator1);
    return suffix ? stripSuffix1(strippedSegment, suffix) : strippedSegment;
}
function extname4(path) {
    assertPath1(path);
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    for(let i = path.length - 1; i >= 0; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator1(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format5(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format1("/", pathObject);
}
function parse6(path) {
    assertPath1(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    if (path.length === 0) return ret;
    const isAbsolute = isPosixPathSeparator1(path.charCodeAt(0));
    let start;
    if (isAbsolute) {
        ret.root = "/";
        start = 1;
    } else {
        start = 0;
    }
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator1(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            if (startPart === 0 && isAbsolute) {
                ret.base = ret.name = path.slice(1, end);
            } else {
                ret.base = ret.name = path.slice(startPart, end);
            }
        }
        ret.base = ret.base || "/";
    } else {
        if (startPart === 0 && isAbsolute) {
            ret.name = path.slice(1, startDot);
            ret.base = path.slice(1, end);
        } else {
            ret.name = path.slice(startPart, startDot);
            ret.base = path.slice(startPart, end);
        }
        ret.ext = path.slice(startDot, end);
    }
    if (startPart > 0) {
        ret.dir = stripTrailingSeparators1(path.slice(0, startPart - 1), isPosixPathSeparator1);
    } else if (isAbsolute) ret.dir = "/";
    return ret;
}
function fromFileUrl4(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    return decodeURIComponent(url.pathname.replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
}
function toFileUrl4(path) {
    if (!isAbsolute4(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const url = new URL("file:///");
    url.pathname = encodeWhitespace1(path.replace(/%/g, "%25").replace(/\\/g, "%5C"));
    return url;
}
const mod3 = {
    sep: sep4,
    delimiter: delimiter4,
    resolve: resolve4,
    normalize: normalize6,
    isAbsolute: isAbsolute4,
    join: join5,
    relative: relative4,
    toNamespacedPath: toNamespacedPath4,
    dirname: dirname4,
    basename: basename4,
    extname: extname4,
    format: format5,
    parse: parse6,
    fromFileUrl: fromFileUrl4,
    toFileUrl: toFileUrl4
};
const path2 = isWindows1 ? mod2 : mod3;
const { join: join6, normalize: normalize7 } = path2;
const path3 = isWindows1 ? mod2 : mod3;
const { basename: basename5, delimiter: delimiter5, dirname: dirname5, extname: extname5, format: format6, fromFileUrl: fromFileUrl5, isAbsolute: isAbsolute5, join: join7, normalize: normalize8, parse: parse7, relative: relative5, resolve: resolve5, toFileUrl: toFileUrl5, toNamespacedPath: toNamespacedPath5 } = path3;
path3.sep;
class DenoStdInternalError2 extends Error {
    constructor(message){
        super(message);
        this.name = "DenoStdInternalError";
    }
}
function assert3(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError2(msg);
    }
}
function copy1(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
const MIN_READ1 = 32 * 1024;
const MAX_SIZE2 = 2 ** 32 - 2;
class Buffer2 {
    #buf;
    #off = 0;
    constructor(ab){
        this.#buf = ab === undefined ? new Uint8Array(0) : new Uint8Array(ab);
    }
    bytes(options = {
        copy: true
    }) {
        if (options.copy === false) return this.#buf.subarray(this.#off);
        return this.#buf.slice(this.#off);
    }
    empty() {
        return this.#buf.byteLength <= this.#off;
    }
    get length() {
        return this.#buf.byteLength - this.#off;
    }
    get capacity() {
        return this.#buf.buffer.byteLength;
    }
    truncate(n) {
        if (n === 0) {
            this.reset();
            return;
        }
        if (n < 0 || n > this.length) {
            throw Error("bytes.Buffer: truncation out of range");
        }
        this.#reslice(this.#off + n);
    }
    reset() {
        this.#reslice(0);
        this.#off = 0;
    }
    #tryGrowByReslice(n) {
        const l = this.#buf.byteLength;
        if (n <= this.capacity - l) {
            this.#reslice(l + n);
            return l;
        }
        return -1;
    }
    #reslice(len) {
        assert3(len <= this.#buf.buffer.byteLength);
        this.#buf = new Uint8Array(this.#buf.buffer, 0, len);
    }
    readSync(p) {
        if (this.empty()) {
            this.reset();
            if (p.byteLength === 0) {
                return 0;
            }
            return null;
        }
        const nread = copy1(this.#buf.subarray(this.#off), p);
        this.#off += nread;
        return nread;
    }
    read(p) {
        const rr = this.readSync(p);
        return Promise.resolve(rr);
    }
    writeSync(p) {
        const m = this.#grow(p.byteLength);
        return copy1(p, this.#buf, m);
    }
    write(p) {
        const n = this.writeSync(p);
        return Promise.resolve(n);
    }
    #grow(n) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n <= Math.floor(c / 2) - m) {
            copy1(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n > MAX_SIZE2) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE2));
            copy1(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n, MAX_SIZE2));
        return m;
    }
    grow(n) {
        if (n < 0) {
            throw Error("Buffer.grow: negative count");
        }
        const m = this.#grow(n);
        this.#reslice(m);
    }
    async readFrom(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ1);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ1;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = await r.read(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
    readFromSync(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ1);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ1;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = r.readSync(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
}
async function readAll1(r) {
    const buf = new Buffer2();
    await buf.readFrom(r);
    return buf.bytes();
}
const other = {
    "audio/x-opus": [
        "opus"
    ],
    "application/prs.cww": [
        "cww"
    ],
    "application/vnd.1000minds.decision-model+xml": [
        "1km"
    ],
    "application/vnd.3gpp.pic-bw-large": [
        "plb"
    ],
    "application/vnd.3gpp.pic-bw-small": [
        "psb"
    ],
    "application/vnd.3gpp.pic-bw-var": [
        "pvb"
    ],
    "application/vnd.3gpp2.tcap": [
        "tcap"
    ],
    "application/vnd.3m.post-it-notes": [
        "pwn"
    ],
    "application/vnd.accpac.simply.aso": [
        "aso"
    ],
    "application/vnd.accpac.simply.imp": [
        "imp"
    ],
    "application/vnd.acucobol": [
        "acu"
    ],
    "application/vnd.acucorp": [
        "atc",
        "acutc"
    ],
    "application/vnd.adobe.air-application-installer-package+zip": [
        "air"
    ],
    "application/vnd.adobe.formscentral.fcdt": [
        "fcdt"
    ],
    "application/vnd.adobe.fxp": [
        "fxp",
        "fxpl"
    ],
    "application/vnd.adobe.xdp+xml": [
        "xdp"
    ],
    "application/vnd.adobe.xfdf": [
        "xfdf"
    ],
    "application/vnd.ahead.space": [
        "ahead"
    ],
    "application/vnd.airzip.filesecure.azf": [
        "azf"
    ],
    "application/vnd.airzip.filesecure.azs": [
        "azs"
    ],
    "application/vnd.amazon.ebook": [
        "azw"
    ],
    "application/vnd.americandynamics.acc": [
        "acc"
    ],
    "application/vnd.amiga.ami": [
        "ami"
    ],
    "application/vnd.android.package-archive": [
        "apk"
    ],
    "application/vnd.anser-web-certificate-issue-initiation": [
        "cii"
    ],
    "application/vnd.anser-web-funds-transfer-initiation": [
        "fti"
    ],
    "application/vnd.antix.game-component": [
        "atx"
    ],
    "application/vnd.apple.installer+xml": [
        "mpkg"
    ],
    "application/vnd.apple.keynote": [
        "key"
    ],
    "application/vnd.apple.mpegurl": [
        "m3u8"
    ],
    "application/vnd.apple.numbers": [
        "numbers"
    ],
    "application/vnd.apple.pages": [
        "pages"
    ],
    "application/vnd.apple.pkpass": [
        "pkpass"
    ],
    "application/vnd.aristanetworks.swi": [
        "swi"
    ],
    "application/vnd.astraea-software.iota": [
        "iota"
    ],
    "application/vnd.audiograph": [
        "aep"
    ],
    "application/vnd.balsamiq.bmml+xml": [
        "bmml"
    ],
    "application/vnd.blueice.multipass": [
        "mpm"
    ],
    "application/vnd.bmi": [
        "bmi"
    ],
    "application/vnd.businessobjects": [
        "rep"
    ],
    "application/vnd.chemdraw+xml": [
        "cdxml"
    ],
    "application/vnd.chipnuts.karaoke-mmd": [
        "mmd"
    ],
    "application/vnd.cinderella": [
        "cdy"
    ],
    "application/vnd.citationstyles.style+xml": [
        "csl"
    ],
    "application/vnd.claymore": [
        "cla"
    ],
    "application/vnd.cloanto.rp9": [
        "rp9"
    ],
    "application/vnd.clonk.c4group": [
        "c4g",
        "c4d",
        "c4f",
        "c4p",
        "c4u"
    ],
    "application/vnd.cluetrust.cartomobile-config": [
        "c11amc"
    ],
    "application/vnd.cluetrust.cartomobile-config-pkg": [
        "c11amz"
    ],
    "application/vnd.commonspace": [
        "csp"
    ],
    "application/vnd.contact.cmsg": [
        "cdbcmsg"
    ],
    "application/vnd.cosmocaller": [
        "cmc"
    ],
    "application/vnd.crick.clicker": [
        "clkx"
    ],
    "application/vnd.crick.clicker.keyboard": [
        "clkk"
    ],
    "application/vnd.crick.clicker.palette": [
        "clkp"
    ],
    "application/vnd.crick.clicker.template": [
        "clkt"
    ],
    "application/vnd.crick.clicker.wordbank": [
        "clkw"
    ],
    "application/vnd.criticaltools.wbs+xml": [
        "wbs"
    ],
    "application/vnd.ctc-posml": [
        "pml"
    ],
    "application/vnd.cups-ppd": [
        "ppd"
    ],
    "application/vnd.curl.car": [
        "car"
    ],
    "application/vnd.curl.pcurl": [
        "pcurl"
    ],
    "application/vnd.dart": [
        "dart"
    ],
    "application/vnd.data-vision.rdz": [
        "rdz"
    ],
    "application/vnd.dbf": [
        "dbf"
    ],
    "application/vnd.dece.data": [
        "uvf",
        "uvvf",
        "uvd",
        "uvvd"
    ],
    "application/vnd.dece.ttml+xml": [
        "uvt",
        "uvvt"
    ],
    "application/vnd.dece.unspecified": [
        "uvx",
        "uvvx"
    ],
    "application/vnd.dece.zip": [
        "uvz",
        "uvvz"
    ],
    "application/vnd.denovo.fcselayout-link": [
        "fe_launch"
    ],
    "application/vnd.dna": [
        "dna"
    ],
    "application/vnd.dolby.mlp": [
        "mlp"
    ],
    "application/vnd.dpgraph": [
        "dpg"
    ],
    "application/vnd.dreamfactory": [
        "dfac"
    ],
    "application/vnd.ds-keypoint": [
        "kpxx"
    ],
    "application/vnd.dvb.ait": [
        "ait"
    ],
    "application/vnd.dvb.service": [
        "svc"
    ],
    "application/vnd.dynageo": [
        "geo"
    ],
    "application/vnd.ecowin.chart": [
        "mag"
    ],
    "application/vnd.enliven": [
        "nml"
    ],
    "application/vnd.epson.esf": [
        "esf"
    ],
    "application/vnd.epson.msf": [
        "msf"
    ],
    "application/vnd.epson.quickanime": [
        "qam"
    ],
    "application/vnd.epson.salt": [
        "slt"
    ],
    "application/vnd.epson.ssf": [
        "ssf"
    ],
    "application/vnd.eszigno3+xml": [
        "es3",
        "et3"
    ],
    "application/vnd.ezpix-album": [
        "ez2"
    ],
    "application/vnd.ezpix-package": [
        "ez3"
    ],
    "application/vnd.fdf": [
        "fdf"
    ],
    "application/vnd.fdsn.mseed": [
        "mseed"
    ],
    "application/vnd.fdsn.seed": [
        "seed",
        "dataless"
    ],
    "application/vnd.flographit": [
        "gph"
    ],
    "application/vnd.fluxtime.clip": [
        "ftc"
    ],
    "application/vnd.framemaker": [
        "fm",
        "frame",
        "maker",
        "book"
    ],
    "application/vnd.frogans.fnc": [
        "fnc"
    ],
    "application/vnd.frogans.ltf": [
        "ltf"
    ],
    "application/vnd.fsc.weblaunch": [
        "fsc"
    ],
    "application/vnd.fujitsu.oasys": [
        "oas"
    ],
    "application/vnd.fujitsu.oasys2": [
        "oa2"
    ],
    "application/vnd.fujitsu.oasys3": [
        "oa3"
    ],
    "application/vnd.fujitsu.oasysgp": [
        "fg5"
    ],
    "application/vnd.fujitsu.oasysprs": [
        "bh2"
    ],
    "application/vnd.fujixerox.ddd": [
        "ddd"
    ],
    "application/vnd.fujixerox.docuworks": [
        "xdw"
    ],
    "application/vnd.fujixerox.docuworks.binder": [
        "xbd"
    ],
    "application/vnd.fuzzysheet": [
        "fzs"
    ],
    "application/vnd.genomatix.tuxedo": [
        "txd"
    ],
    "application/vnd.geogebra.file": [
        "ggb"
    ],
    "application/vnd.geogebra.tool": [
        "ggt"
    ],
    "application/vnd.geometry-explorer": [
        "gex",
        "gre"
    ],
    "application/vnd.geonext": [
        "gxt"
    ],
    "application/vnd.geoplan": [
        "g2w"
    ],
    "application/vnd.geospace": [
        "g3w"
    ],
    "application/vnd.gmx": [
        "gmx"
    ],
    "application/vnd.google-apps.document": [
        "gdoc"
    ],
    "application/vnd.google-apps.presentation": [
        "gslides"
    ],
    "application/vnd.google-apps.spreadsheet": [
        "gsheet"
    ],
    "application/vnd.google-earth.kml+xml": [
        "kml"
    ],
    "application/vnd.google-earth.kmz": [
        "kmz"
    ],
    "application/vnd.grafeq": [
        "gqf",
        "gqs"
    ],
    "application/vnd.groove-account": [
        "gac"
    ],
    "application/vnd.groove-help": [
        "ghf"
    ],
    "application/vnd.groove-identity-message": [
        "gim"
    ],
    "application/vnd.groove-injector": [
        "grv"
    ],
    "application/vnd.groove-tool-message": [
        "gtm"
    ],
    "application/vnd.groove-tool-template": [
        "tpl"
    ],
    "application/vnd.groove-vcard": [
        "vcg"
    ],
    "application/vnd.hal+xml": [
        "hal"
    ],
    "application/vnd.handheld-entertainment+xml": [
        "zmm"
    ],
    "application/vnd.hbci": [
        "hbci"
    ],
    "application/vnd.hhe.lesson-player": [
        "les"
    ],
    "application/vnd.hp-hpgl": [
        "hpgl"
    ],
    "application/vnd.hp-hpid": [
        "hpid"
    ],
    "application/vnd.hp-hps": [
        "hps"
    ],
    "application/vnd.hp-jlyt": [
        "jlt"
    ],
    "application/vnd.hp-pcl": [
        "pcl"
    ],
    "application/vnd.hp-pclxl": [
        "pclxl"
    ],
    "application/vnd.hydrostatix.sof-data": [
        "sfd-hdstx"
    ],
    "application/vnd.ibm.minipay": [
        "mpy"
    ],
    "application/vnd.ibm.modcap": [
        "afp",
        "listafp",
        "list3820"
    ],
    "application/vnd.ibm.rights-management": [
        "irm"
    ],
    "application/vnd.ibm.secure-container": [
        "sc"
    ],
    "application/vnd.iccprofile": [
        "icc",
        "icm"
    ],
    "application/vnd.igloader": [
        "igl"
    ],
    "application/vnd.immervision-ivp": [
        "ivp"
    ],
    "application/vnd.immervision-ivu": [
        "ivu"
    ],
    "application/vnd.insors.igm": [
        "igm"
    ],
    "application/vnd.intercon.formnet": [
        "xpw",
        "xpx"
    ],
    "application/vnd.intergeo": [
        "i2g"
    ],
    "application/vnd.intu.qbo": [
        "qbo"
    ],
    "application/vnd.intu.qfx": [
        "qfx"
    ],
    "application/vnd.ipunplugged.rcprofile": [
        "rcprofile"
    ],
    "application/vnd.irepository.package+xml": [
        "irp"
    ],
    "application/vnd.is-xpr": [
        "xpr"
    ],
    "application/vnd.isac.fcs": [
        "fcs"
    ],
    "application/vnd.jam": [
        "jam"
    ],
    "application/vnd.jcp.javame.midlet-rms": [
        "rms"
    ],
    "application/vnd.jisp": [
        "jisp"
    ],
    "application/vnd.joost.joda-archive": [
        "joda"
    ],
    "application/vnd.kahootz": [
        "ktz",
        "ktr"
    ],
    "application/vnd.kde.karbon": [
        "karbon"
    ],
    "application/vnd.kde.kchart": [
        "chrt"
    ],
    "application/vnd.kde.kformula": [
        "kfo"
    ],
    "application/vnd.kde.kivio": [
        "flw"
    ],
    "application/vnd.kde.kontour": [
        "kon"
    ],
    "application/vnd.kde.kpresenter": [
        "kpr",
        "kpt"
    ],
    "application/vnd.kde.kspread": [
        "ksp"
    ],
    "application/vnd.kde.kword": [
        "kwd",
        "kwt"
    ],
    "application/vnd.kenameaapp": [
        "htke"
    ],
    "application/vnd.kidspiration": [
        "kia"
    ],
    "application/vnd.kinar": [
        "kne",
        "knp"
    ],
    "application/vnd.koan": [
        "skp",
        "skd",
        "skt",
        "skm"
    ],
    "application/vnd.kodak-descriptor": [
        "sse"
    ],
    "application/vnd.las.las+xml": [
        "lasxml"
    ],
    "application/vnd.llamagraphics.life-balance.desktop": [
        "lbd"
    ],
    "application/vnd.llamagraphics.life-balance.exchange+xml": [
        "lbe"
    ],
    "application/vnd.lotus-1-2-3": [
        "123"
    ],
    "application/vnd.lotus-approach": [
        "apr"
    ],
    "application/vnd.lotus-freelance": [
        "pre"
    ],
    "application/vnd.lotus-notes": [
        "nsf"
    ],
    "application/vnd.lotus-organizer": [
        "org"
    ],
    "application/vnd.lotus-screencam": [
        "scm"
    ],
    "application/vnd.lotus-wordpro": [
        "lwp"
    ],
    "application/vnd.macports.portpkg": [
        "portpkg"
    ],
    "application/vnd.mcd": [
        "mcd"
    ],
    "application/vnd.medcalcdata": [
        "mc1"
    ],
    "application/vnd.mediastation.cdkey": [
        "cdkey"
    ],
    "application/vnd.mfer": [
        "mwf"
    ],
    "application/vnd.mfmp": [
        "mfm"
    ],
    "application/vnd.micrografx.flo": [
        "flo"
    ],
    "application/vnd.micrografx.igx": [
        "igx"
    ],
    "application/vnd.mif": [
        "mif"
    ],
    "application/vnd.mobius.daf": [
        "daf"
    ],
    "application/vnd.mobius.dis": [
        "dis"
    ],
    "application/vnd.mobius.mbk": [
        "mbk"
    ],
    "application/vnd.mobius.mqy": [
        "mqy"
    ],
    "application/vnd.mobius.msl": [
        "msl"
    ],
    "application/vnd.mobius.plc": [
        "plc"
    ],
    "application/vnd.mobius.txf": [
        "txf"
    ],
    "application/vnd.mophun.application": [
        "mpn"
    ],
    "application/vnd.mophun.certificate": [
        "mpc"
    ],
    "application/vnd.mozilla.xul+xml": [
        "xul"
    ],
    "application/vnd.ms-artgalry": [
        "cil"
    ],
    "application/vnd.ms-cab-compressed": [
        "cab"
    ],
    "application/vnd.ms-excel": [
        "xls",
        "xlm",
        "xla",
        "xlc",
        "xlt",
        "xlw"
    ],
    "application/vnd.ms-excel.addin.macroenabled.12": [
        "xlam"
    ],
    "application/vnd.ms-excel.sheet.binary.macroenabled.12": [
        "xlsb"
    ],
    "application/vnd.ms-excel.sheet.macroenabled.12": [
        "xlsm"
    ],
    "application/vnd.ms-excel.template.macroenabled.12": [
        "xltm"
    ],
    "application/vnd.ms-fontobject": [
        "eot"
    ],
    "application/vnd.ms-htmlhelp": [
        "chm"
    ],
    "application/vnd.ms-ims": [
        "ims"
    ],
    "application/vnd.ms-lrm": [
        "lrm"
    ],
    "application/vnd.ms-officetheme": [
        "thmx"
    ],
    "application/vnd.ms-outlook": [
        "msg"
    ],
    "application/vnd.ms-pki.seccat": [
        "cat"
    ],
    "application/vnd.ms-pki.stl": [
        "*stl"
    ],
    "application/vnd.ms-powerpoint": [
        "ppt",
        "pps",
        "pot"
    ],
    "application/vnd.ms-powerpoint.addin.macroenabled.12": [
        "ppam"
    ],
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": [
        "pptm"
    ],
    "application/vnd.ms-powerpoint.slide.macroenabled.12": [
        "sldm"
    ],
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12": [
        "ppsm"
    ],
    "application/vnd.ms-powerpoint.template.macroenabled.12": [
        "potm"
    ],
    "application/vnd.ms-project": [
        "mpp",
        "mpt"
    ],
    "application/vnd.ms-word.document.macroenabled.12": [
        "docm"
    ],
    "application/vnd.ms-word.template.macroenabled.12": [
        "dotm"
    ],
    "application/vnd.ms-works": [
        "wps",
        "wks",
        "wcm",
        "wdb"
    ],
    "application/vnd.ms-wpl": [
        "wpl"
    ],
    "application/vnd.ms-xpsdocument": [
        "xps"
    ],
    "application/vnd.mseq": [
        "mseq"
    ],
    "application/vnd.musician": [
        "mus"
    ],
    "application/vnd.muvee.style": [
        "msty"
    ],
    "application/vnd.mynfc": [
        "taglet"
    ],
    "application/vnd.neurolanguage.nlu": [
        "nlu"
    ],
    "application/vnd.nitf": [
        "ntf",
        "nitf"
    ],
    "application/vnd.noblenet-directory": [
        "nnd"
    ],
    "application/vnd.noblenet-sealer": [
        "nns"
    ],
    "application/vnd.noblenet-web": [
        "nnw"
    ],
    "application/vnd.nokia.n-gage.ac+xml": [
        "*ac"
    ],
    "application/vnd.nokia.n-gage.data": [
        "ngdat"
    ],
    "application/vnd.nokia.n-gage.symbian.install": [
        "n-gage"
    ],
    "application/vnd.nokia.radio-preset": [
        "rpst"
    ],
    "application/vnd.nokia.radio-presets": [
        "rpss"
    ],
    "application/vnd.novadigm.edm": [
        "edm"
    ],
    "application/vnd.novadigm.edx": [
        "edx"
    ],
    "application/vnd.novadigm.ext": [
        "ext"
    ],
    "application/vnd.oasis.opendocument.chart": [
        "odc"
    ],
    "application/vnd.oasis.opendocument.chart-template": [
        "otc"
    ],
    "application/vnd.oasis.opendocument.database": [
        "odb"
    ],
    "application/vnd.oasis.opendocument.formula": [
        "odf"
    ],
    "application/vnd.oasis.opendocument.formula-template": [
        "odft"
    ],
    "application/vnd.oasis.opendocument.graphics": [
        "odg"
    ],
    "application/vnd.oasis.opendocument.graphics-template": [
        "otg"
    ],
    "application/vnd.oasis.opendocument.image": [
        "odi"
    ],
    "application/vnd.oasis.opendocument.image-template": [
        "oti"
    ],
    "application/vnd.oasis.opendocument.presentation": [
        "odp"
    ],
    "application/vnd.oasis.opendocument.presentation-template": [
        "otp"
    ],
    "application/vnd.oasis.opendocument.spreadsheet": [
        "ods"
    ],
    "application/vnd.oasis.opendocument.spreadsheet-template": [
        "ots"
    ],
    "application/vnd.oasis.opendocument.text": [
        "odt"
    ],
    "application/vnd.oasis.opendocument.text-master": [
        "odm"
    ],
    "application/vnd.oasis.opendocument.text-template": [
        "ott"
    ],
    "application/vnd.oasis.opendocument.text-web": [
        "oth"
    ],
    "application/vnd.olpc-sugar": [
        "xo"
    ],
    "application/vnd.oma.dd2+xml": [
        "dd2"
    ],
    "application/vnd.openblox.game+xml": [
        "obgx"
    ],
    "application/vnd.openofficeorg.extension": [
        "oxt"
    ],
    "application/vnd.openstreetmap.data+xml": [
        "osm"
    ],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": [
        "pptx"
    ],
    "application/vnd.openxmlformats-officedocument.presentationml.slide": [
        "sldx"
    ],
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow": [
        "ppsx"
    ],
    "application/vnd.openxmlformats-officedocument.presentationml.template": [
        "potx"
    ],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
        "xlsx"
    ],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template": [
        "xltx"
    ],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
        "docx"
    ],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template": [
        "dotx"
    ],
    "application/vnd.osgeo.mapguide.package": [
        "mgp"
    ],
    "application/vnd.osgi.dp": [
        "dp"
    ],
    "application/vnd.osgi.subsystem": [
        "esa"
    ],
    "application/vnd.palm": [
        "pdb",
        "pqa",
        "oprc"
    ],
    "application/vnd.pawaafile": [
        "paw"
    ],
    "application/vnd.pg.format": [
        "str"
    ],
    "application/vnd.pg.osasli": [
        "ei6"
    ],
    "application/vnd.picsel": [
        "efif"
    ],
    "application/vnd.pmi.widget": [
        "wg"
    ],
    "application/vnd.pocketlearn": [
        "plf"
    ],
    "application/vnd.powerbuilder6": [
        "pbd"
    ],
    "application/vnd.previewsystems.box": [
        "box"
    ],
    "application/vnd.proteus.magazine": [
        "mgz"
    ],
    "application/vnd.publishare-delta-tree": [
        "qps"
    ],
    "application/vnd.pvi.ptid1": [
        "ptid"
    ],
    "application/vnd.quark.quarkxpress": [
        "qxd",
        "qxt",
        "qwd",
        "qwt",
        "qxl",
        "qxb"
    ],
    "application/vnd.rar": [
        "rar"
    ],
    "application/vnd.realvnc.bed": [
        "bed"
    ],
    "application/vnd.recordare.musicxml": [
        "mxl"
    ],
    "application/vnd.recordare.musicxml+xml": [
        "musicxml"
    ],
    "application/vnd.rig.cryptonote": [
        "cryptonote"
    ],
    "application/vnd.rim.cod": [
        "cod"
    ],
    "application/vnd.rn-realmedia": [
        "rm"
    ],
    "application/vnd.rn-realmedia-vbr": [
        "rmvb"
    ],
    "application/vnd.route66.link66+xml": [
        "link66"
    ],
    "application/vnd.sailingtracker.track": [
        "st"
    ],
    "application/vnd.seemail": [
        "see"
    ],
    "application/vnd.sema": [
        "sema"
    ],
    "application/vnd.semd": [
        "semd"
    ],
    "application/vnd.semf": [
        "semf"
    ],
    "application/vnd.shana.informed.formdata": [
        "ifm"
    ],
    "application/vnd.shana.informed.formtemplate": [
        "itp"
    ],
    "application/vnd.shana.informed.interchange": [
        "iif"
    ],
    "application/vnd.shana.informed.package": [
        "ipk"
    ],
    "application/vnd.simtech-mindmapper": [
        "twd",
        "twds"
    ],
    "application/vnd.smaf": [
        "mmf"
    ],
    "application/vnd.smart.teacher": [
        "teacher"
    ],
    "application/vnd.software602.filler.form+xml": [
        "fo"
    ],
    "application/vnd.solent.sdkm+xml": [
        "sdkm",
        "sdkd"
    ],
    "application/vnd.spotfire.dxp": [
        "dxp"
    ],
    "application/vnd.spotfire.sfs": [
        "sfs"
    ],
    "application/vnd.stardivision.calc": [
        "sdc"
    ],
    "application/vnd.stardivision.draw": [
        "sda"
    ],
    "application/vnd.stardivision.impress": [
        "sdd"
    ],
    "application/vnd.stardivision.math": [
        "smf"
    ],
    "application/vnd.stardivision.writer": [
        "sdw",
        "vor"
    ],
    "application/vnd.stardivision.writer-global": [
        "sgl"
    ],
    "application/vnd.stepmania.package": [
        "smzip"
    ],
    "application/vnd.stepmania.stepchart": [
        "sm"
    ],
    "application/vnd.sun.wadl+xml": [
        "wadl"
    ],
    "application/vnd.sun.xml.calc": [
        "sxc"
    ],
    "application/vnd.sun.xml.calc.template": [
        "stc"
    ],
    "application/vnd.sun.xml.draw": [
        "sxd"
    ],
    "application/vnd.sun.xml.draw.template": [
        "std"
    ],
    "application/vnd.sun.xml.impress": [
        "sxi"
    ],
    "application/vnd.sun.xml.impress.template": [
        "sti"
    ],
    "application/vnd.sun.xml.math": [
        "sxm"
    ],
    "application/vnd.sun.xml.writer": [
        "sxw"
    ],
    "application/vnd.sun.xml.writer.global": [
        "sxg"
    ],
    "application/vnd.sun.xml.writer.template": [
        "stw"
    ],
    "application/vnd.sus-calendar": [
        "sus",
        "susp"
    ],
    "application/vnd.svd": [
        "svd"
    ],
    "application/vnd.symbian.install": [
        "sis",
        "sisx"
    ],
    "application/vnd.syncml+xml": [
        "xsm"
    ],
    "application/vnd.syncml.dm+wbxml": [
        "bdm"
    ],
    "application/vnd.syncml.dm+xml": [
        "xdm"
    ],
    "application/vnd.syncml.dmddf+xml": [
        "ddf"
    ],
    "application/vnd.tao.intent-module-archive": [
        "tao"
    ],
    "application/vnd.tcpdump.pcap": [
        "pcap",
        "cap",
        "dmp"
    ],
    "application/vnd.tmobile-livetv": [
        "tmo"
    ],
    "application/vnd.trid.tpt": [
        "tpt"
    ],
    "application/vnd.triscape.mxs": [
        "mxs"
    ],
    "application/vnd.trueapp": [
        "tra"
    ],
    "application/vnd.ufdl": [
        "ufd",
        "ufdl"
    ],
    "application/vnd.uiq.theme": [
        "utz"
    ],
    "application/vnd.umajin": [
        "umj"
    ],
    "application/vnd.unity": [
        "unityweb"
    ],
    "application/vnd.uoml+xml": [
        "uoml"
    ],
    "application/vnd.vcx": [
        "vcx"
    ],
    "application/vnd.visio": [
        "vsd",
        "vst",
        "vss",
        "vsw"
    ],
    "application/vnd.visionary": [
        "vis"
    ],
    "application/vnd.vsf": [
        "vsf"
    ],
    "application/vnd.wap.wbxml": [
        "wbxml"
    ],
    "application/vnd.wap.wmlc": [
        "wmlc"
    ],
    "application/vnd.wap.wmlscriptc": [
        "wmlsc"
    ],
    "application/vnd.webturbo": [
        "wtb"
    ],
    "application/vnd.wolfram.player": [
        "nbp"
    ],
    "application/vnd.wordperfect": [
        "wpd"
    ],
    "application/vnd.wqd": [
        "wqd"
    ],
    "application/vnd.wt.stf": [
        "stf"
    ],
    "application/vnd.xara": [
        "xar"
    ],
    "application/vnd.xfdl": [
        "xfdl"
    ],
    "application/vnd.yamaha.hv-dic": [
        "hvd"
    ],
    "application/vnd.yamaha.hv-script": [
        "hvs"
    ],
    "application/vnd.yamaha.hv-voice": [
        "hvp"
    ],
    "application/vnd.yamaha.openscoreformat": [
        "osf"
    ],
    "application/vnd.yamaha.openscoreformat.osfpvg+xml": [
        "osfpvg"
    ],
    "application/vnd.yamaha.smaf-audio": [
        "saf"
    ],
    "application/vnd.yamaha.smaf-phrase": [
        "spf"
    ],
    "application/vnd.yellowriver-custom-menu": [
        "cmp"
    ],
    "application/vnd.zul": [
        "zir",
        "zirz"
    ],
    "application/vnd.zzazz.deck+xml": [
        "zaz"
    ],
    "application/x-7z-compressed": [
        "7z"
    ],
    "application/x-abiword": [
        "abw"
    ],
    "application/x-ace-compressed": [
        "ace"
    ],
    "application/x-apple-diskimage": [
        "*dmg"
    ],
    "application/x-arj": [
        "arj"
    ],
    "application/x-authorware-bin": [
        "aab",
        "x32",
        "u32",
        "vox"
    ],
    "application/x-authorware-map": [
        "aam"
    ],
    "application/x-authorware-seg": [
        "aas"
    ],
    "application/x-bcpio": [
        "bcpio"
    ],
    "application/x-bdoc": [
        "*bdoc"
    ],
    "application/x-bittorrent": [
        "torrent"
    ],
    "application/x-blorb": [
        "blb",
        "blorb"
    ],
    "application/x-bzip": [
        "bz"
    ],
    "application/x-bzip2": [
        "bz2",
        "boz"
    ],
    "application/x-cbr": [
        "cbr",
        "cba",
        "cbt",
        "cbz",
        "cb7"
    ],
    "application/x-cdlink": [
        "vcd"
    ],
    "application/x-cfs-compressed": [
        "cfs"
    ],
    "application/x-chat": [
        "chat"
    ],
    "application/x-chess-pgn": [
        "pgn"
    ],
    "application/x-chrome-extension": [
        "crx"
    ],
    "application/x-cocoa": [
        "cco"
    ],
    "application/x-conference": [
        "nsc"
    ],
    "application/x-cpio": [
        "cpio"
    ],
    "application/x-csh": [
        "csh"
    ],
    "application/x-debian-package": [
        "*deb",
        "udeb"
    ],
    "application/x-dgc-compressed": [
        "dgc"
    ],
    "application/x-director": [
        "dir",
        "dcr",
        "dxr",
        "cst",
        "cct",
        "cxt",
        "w3d",
        "fgd",
        "swa"
    ],
    "application/x-doom": [
        "wad"
    ],
    "application/x-dtbncx+xml": [
        "ncx"
    ],
    "application/x-dtbook+xml": [
        "dtb"
    ],
    "application/x-dtbresource+xml": [
        "res"
    ],
    "application/x-dvi": [
        "dvi"
    ],
    "application/x-envoy": [
        "evy"
    ],
    "application/x-eva": [
        "eva"
    ],
    "application/x-font-bdf": [
        "bdf"
    ],
    "application/x-font-ghostscript": [
        "gsf"
    ],
    "application/x-font-linux-psf": [
        "psf"
    ],
    "application/x-font-pcf": [
        "pcf"
    ],
    "application/x-font-snf": [
        "snf"
    ],
    "application/x-font-type1": [
        "pfa",
        "pfb",
        "pfm",
        "afm"
    ],
    "application/x-freearc": [
        "arc"
    ],
    "application/x-futuresplash": [
        "spl"
    ],
    "application/x-gca-compressed": [
        "gca"
    ],
    "application/x-glulx": [
        "ulx"
    ],
    "application/x-gnumeric": [
        "gnumeric"
    ],
    "application/x-gramps-xml": [
        "gramps"
    ],
    "application/x-gtar": [
        "gtar"
    ],
    "application/x-hdf": [
        "hdf"
    ],
    "application/php": [
        "php"
    ],
    "application/x-install-instructions": [
        "install"
    ],
    "application/x-iso9660-image": [
        "*iso"
    ],
    "application/x-java-archive-diff": [
        "jardiff"
    ],
    "application/x-java-jnlp-file": [
        "jnlp"
    ],
    "application/x-keepass2": [
        "kdbx"
    ],
    "application/x-latex": [
        "latex"
    ],
    "application/x-lua-bytecode": [
        "luac"
    ],
    "application/x-lzh-compressed": [
        "lzh",
        "lha"
    ],
    "application/x-makeself": [
        "run"
    ],
    "application/x-mie": [
        "mie"
    ],
    "application/x-mobipocket-ebook": [
        "prc",
        "mobi"
    ],
    "application/x-ms-application": [
        "application"
    ],
    "application/x-ms-shortcut": [
        "lnk"
    ],
    "application/x-ms-wmd": [
        "wmd"
    ],
    "application/x-ms-wmz": [
        "wmz"
    ],
    "application/x-ms-xbap": [
        "xbap"
    ],
    "application/x-msaccess": [
        "mdb"
    ],
    "application/x-msbinder": [
        "obd"
    ],
    "application/x-mscardfile": [
        "crd"
    ],
    "application/x-msclip": [
        "clp"
    ],
    "application/x-msdos-program": [
        "*exe"
    ],
    "application/x-msdownload": [
        "*exe",
        "*dll",
        "com",
        "bat",
        "*msi"
    ],
    "application/x-msmediaview": [
        "mvb",
        "m13",
        "m14"
    ],
    "application/x-msmetafile": [
        "*wmf",
        "*wmz",
        "*emf",
        "emz"
    ],
    "application/x-msmoney": [
        "mny"
    ],
    "application/x-mspublisher": [
        "pub"
    ],
    "application/x-msschedule": [
        "scd"
    ],
    "application/x-msterminal": [
        "trm"
    ],
    "application/x-mswrite": [
        "wri"
    ],
    "application/x-netcdf": [
        "nc",
        "cdf"
    ],
    "application/x-ns-proxy-autoconfig": [
        "pac"
    ],
    "application/x-nzb": [
        "nzb"
    ],
    "application/x-perl": [
        "pl",
        "pm"
    ],
    "application/x-pilot": [
        "*prc",
        "*pdb"
    ],
    "application/x-pkcs12": [
        "p12",
        "pfx"
    ],
    "application/x-pkcs7-certificates": [
        "p7b",
        "spc"
    ],
    "application/x-pkcs7-certreqresp": [
        "p7r"
    ],
    "application/x-rar-compressed": [
        "*rar"
    ],
    "application/x-redhat-package-manager": [
        "rpm"
    ],
    "application/x-research-info-systems": [
        "ris"
    ],
    "application/x-sea": [
        "sea"
    ],
    "application/x-sh": [
        "sh"
    ],
    "application/x-shar": [
        "shar"
    ],
    "application/x-shockwave-flash": [
        "swf"
    ],
    "application/x-silverlight-app": [
        "xap"
    ],
    "application/x-sql": [
        "sql"
    ],
    "application/x-stuffit": [
        "sit"
    ],
    "application/x-stuffitx": [
        "sitx"
    ],
    "application/x-subrip": [
        "srt"
    ],
    "application/x-sv4cpio": [
        "sv4cpio"
    ],
    "application/x-sv4crc": [
        "sv4crc"
    ],
    "application/x-t3vm-image": [
        "t3"
    ],
    "application/x-tads": [
        "gam"
    ],
    "application/x-tar": [
        "tar"
    ],
    "application/x-tcl": [
        "tcl",
        "tk"
    ],
    "application/x-tex": [
        "tex"
    ],
    "application/x-tex-tfm": [
        "tfm"
    ],
    "application/x-texinfo": [
        "texinfo",
        "texi"
    ],
    "application/x-tgif": [
        "*obj"
    ],
    "application/x-ustar": [
        "ustar"
    ],
    "application/x-virtualbox-hdd": [
        "hdd"
    ],
    "application/x-virtualbox-ova": [
        "ova"
    ],
    "application/x-virtualbox-ovf": [
        "ovf"
    ],
    "application/x-virtualbox-vbox": [
        "vbox"
    ],
    "application/x-virtualbox-vbox-extpack": [
        "vbox-extpack"
    ],
    "application/x-virtualbox-vdi": [
        "vdi"
    ],
    "application/x-virtualbox-vhd": [
        "vhd"
    ],
    "application/x-virtualbox-vmdk": [
        "vmdk"
    ],
    "application/x-wais-source": [
        "src"
    ],
    "application/x-web-app-manifest+json": [
        "webapp"
    ],
    "application/x-x509-ca-cert": [
        "der",
        "crt",
        "pem"
    ],
    "application/x-xfig": [
        "fig"
    ],
    "application/x-xliff+xml": [
        "*xlf"
    ],
    "application/x-xpinstall": [
        "xpi"
    ],
    "application/x-xz": [
        "xz"
    ],
    "application/x-zmachine": [
        "z1",
        "z2",
        "z3",
        "z4",
        "z5",
        "z6",
        "z7",
        "z8"
    ],
    "audio/vnd.dece.audio": [
        "uva",
        "uvva"
    ],
    "audio/vnd.digital-winds": [
        "eol"
    ],
    "audio/vnd.dra": [
        "dra"
    ],
    "audio/vnd.dts": [
        "dts"
    ],
    "audio/vnd.dts.hd": [
        "dtshd"
    ],
    "audio/vnd.lucent.voice": [
        "lvp"
    ],
    "audio/vnd.ms-playready.media.pya": [
        "pya"
    ],
    "audio/vnd.nuera.ecelp4800": [
        "ecelp4800"
    ],
    "audio/vnd.nuera.ecelp7470": [
        "ecelp7470"
    ],
    "audio/vnd.nuera.ecelp9600": [
        "ecelp9600"
    ],
    "audio/vnd.rip": [
        "rip"
    ],
    "audio/x-aiff": [
        "aif",
        "aiff",
        "aifc"
    ],
    "audio/x-caf": [
        "caf"
    ],
    "audio/x-flac": [
        "flac"
    ],
    "audio/x-m4a": [
        "*m4a"
    ],
    "audio/x-matroska": [
        "mka"
    ],
    "audio/x-mpegurl": [
        "m3u"
    ],
    "audio/x-ms-wax": [
        "wax"
    ],
    "audio/x-ms-wma": [
        "wma"
    ],
    "audio/x-pn-realaudio": [
        "ram",
        "ra"
    ],
    "audio/x-pn-realaudio-plugin": [
        "rmp"
    ],
    "audio/x-realaudio": [
        "*ra"
    ],
    "audio/x-wav": [
        "*wav"
    ],
    "chemical/x-cdx": [
        "cdx"
    ],
    "chemical/x-cif": [
        "cif"
    ],
    "chemical/x-cmdf": [
        "cmdf"
    ],
    "chemical/x-cml": [
        "cml"
    ],
    "chemical/x-csml": [
        "csml"
    ],
    "chemical/x-xyz": [
        "xyz"
    ],
    "image/prs.btif": [
        "btif"
    ],
    "image/prs.pti": [
        "pti"
    ],
    "image/vnd.adobe.photoshop": [
        "psd"
    ],
    "image/vnd.airzip.accelerator.azv": [
        "azv"
    ],
    "image/vnd.dece.graphic": [
        "uvi",
        "uvvi",
        "uvg",
        "uvvg"
    ],
    "image/vnd.djvu": [
        "djvu",
        "djv"
    ],
    "image/vnd.dvb.subtitle": [
        "*sub"
    ],
    "image/vnd.dwg": [
        "dwg"
    ],
    "image/vnd.dxf": [
        "dxf"
    ],
    "image/vnd.fastbidsheet": [
        "fbs"
    ],
    "image/vnd.fpx": [
        "fpx"
    ],
    "image/vnd.fst": [
        "fst"
    ],
    "image/vnd.fujixerox.edmics-mmr": [
        "mmr"
    ],
    "image/vnd.fujixerox.edmics-rlc": [
        "rlc"
    ],
    "image/vnd.microsoft.icon": [
        "ico"
    ],
    "image/vnd.ms-dds": [
        "dds"
    ],
    "image/vnd.ms-modi": [
        "mdi"
    ],
    "image/vnd.ms-photo": [
        "wdp"
    ],
    "image/vnd.net-fpx": [
        "npx"
    ],
    "image/vnd.pco.b16": [
        "b16"
    ],
    "image/vnd.tencent.tap": [
        "tap"
    ],
    "image/vnd.valve.source.texture": [
        "vtf"
    ],
    "image/vnd.wap.wbmp": [
        "wbmp"
    ],
    "image/vnd.xiff": [
        "xif"
    ],
    "image/vnd.zbrush.pcx": [
        "pcx"
    ],
    "image/x-3ds": [
        "3ds"
    ],
    "image/x-cmu-raster": [
        "ras"
    ],
    "image/x-cmx": [
        "cmx"
    ],
    "image/x-freehand": [
        "fh",
        "fhc",
        "fh4",
        "fh5",
        "fh7"
    ],
    "image/x-icon": [
        "*ico"
    ],
    "image/x-jng": [
        "jng"
    ],
    "image/x-mrsid-image": [
        "sid"
    ],
    "image/x-ms-bmp": [
        "*bmp"
    ],
    "image/x-pcx": [
        "*pcx"
    ],
    "image/x-pict": [
        "pic",
        "pct"
    ],
    "image/x-portable-anymap": [
        "pnm"
    ],
    "image/x-portable-bitmap": [
        "pbm"
    ],
    "image/x-portable-graymap": [
        "pgm"
    ],
    "image/x-portable-pixmap": [
        "ppm"
    ],
    "image/x-rgb": [
        "rgb"
    ],
    "image/x-tga": [
        "tga"
    ],
    "image/x-xbitmap": [
        "xbm"
    ],
    "image/x-xpixmap": [
        "xpm"
    ],
    "image/x-xwindowdump": [
        "xwd"
    ],
    "message/vnd.wfa.wsc": [
        "wsc"
    ],
    "model/vnd.collada+xml": [
        "dae"
    ],
    "model/vnd.dwf": [
        "dwf"
    ],
    "model/vnd.gdl": [
        "gdl"
    ],
    "model/vnd.gtw": [
        "gtw"
    ],
    "model/vnd.mts": [
        "mts"
    ],
    "model/vnd.opengex": [
        "ogex"
    ],
    "model/vnd.parasolid.transmit.binary": [
        "x_b"
    ],
    "model/vnd.parasolid.transmit.text": [
        "x_t"
    ],
    "model/vnd.usdz+zip": [
        "usdz"
    ],
    "model/vnd.valve.source.compiled-map": [
        "bsp"
    ],
    "model/vnd.vtu": [
        "vtu"
    ],
    "text/prs.lines.tag": [
        "dsc"
    ],
    "text/vnd.curl": [
        "curl"
    ],
    "text/vnd.curl.dcurl": [
        "dcurl"
    ],
    "text/vnd.curl.mcurl": [
        "mcurl"
    ],
    "text/vnd.curl.scurl": [
        "scurl"
    ],
    "text/vnd.dvb.subtitle": [
        "sub"
    ],
    "text/vnd.fly": [
        "fly"
    ],
    "text/vnd.fmi.flexstor": [
        "flx"
    ],
    "text/vnd.graphviz": [
        "gv"
    ],
    "text/vnd.in3d.3dml": [
        "3dml"
    ],
    "text/vnd.in3d.spot": [
        "spot"
    ],
    "text/vnd.sun.j2me.app-descriptor": [
        "jad"
    ],
    "text/vnd.wap.wml": [
        "wml"
    ],
    "text/vnd.wap.wmlscript": [
        "wmls"
    ],
    "text/x-asm": [
        "s",
        "asm"
    ],
    "text/x-c": [
        "c",
        "cc",
        "cxx",
        "cpp",
        "h",
        "hh",
        "dic"
    ],
    "text/x-component": [
        "htc"
    ],
    "text/x-fortran": [
        "f",
        "for",
        "f77",
        "f90"
    ],
    "text/x-handlebars-template": [
        "hbs"
    ],
    "text/x-java-source": [
        "java"
    ],
    "text/x-lua": [
        "lua"
    ],
    "text/x-markdown": [
        "mkd"
    ],
    "text/x-nfo": [
        "nfo"
    ],
    "text/x-opml": [
        "opml"
    ],
    "text/x-org": [
        "*org"
    ],
    "text/x-pascal": [
        "p",
        "pas"
    ],
    "text/x-processing": [
        "pde"
    ],
    "text/x-sass": [
        "sass"
    ],
    "text/x-scss": [
        "scss"
    ],
    "text/x-setext": [
        "etx"
    ],
    "text/x-sfv": [
        "sfv"
    ],
    "text/x-suse-ymp": [
        "ymp"
    ],
    "text/x-uuencode": [
        "uu"
    ],
    "text/x-vcalendar": [
        "vcs"
    ],
    "text/x-vcard": [
        "vcf"
    ],
    "video/vnd.dece.hd": [
        "uvh",
        "uvvh"
    ],
    "video/vnd.dece.mobile": [
        "uvm",
        "uvvm"
    ],
    "video/vnd.dece.pd": [
        "uvp",
        "uvvp"
    ],
    "video/vnd.dece.sd": [
        "uvs",
        "uvvs"
    ],
    "video/vnd.dece.video": [
        "uvv",
        "uvvv"
    ],
    "video/vnd.dvb.file": [
        "dvb"
    ],
    "video/vnd.fvt": [
        "fvt"
    ],
    "video/vnd.mpegurl": [
        "mxu",
        "m4u"
    ],
    "video/vnd.ms-playready.media.pyv": [
        "pyv"
    ],
    "video/vnd.uvvu.mp4": [
        "uvu",
        "uvvu"
    ],
    "video/vnd.vivo": [
        "viv"
    ],
    "video/x-f4v": [
        "f4v"
    ],
    "video/x-fli": [
        "fli"
    ],
    "video/x-flv": [
        "flv"
    ],
    "video/x-m4v": [
        "m4v"
    ],
    "video/x-matroska": [
        "mkv",
        "mk3d",
        "mks"
    ],
    "video/x-mng": [
        "mng"
    ],
    "video/x-ms-asf": [
        "asf",
        "asx"
    ],
    "video/x-ms-vob": [
        "vob"
    ],
    "video/x-ms-wm": [
        "wm"
    ],
    "video/x-ms-wmv": [
        "wmv"
    ],
    "video/x-ms-wmx": [
        "wmx"
    ],
    "video/x-ms-wvx": [
        "wvx"
    ],
    "video/x-msvideo": [
        "avi"
    ],
    "video/x-sgi-movie": [
        "movie"
    ],
    "video/x-smv": [
        "smv"
    ],
    "x-conference/x-cooltalk": [
        "ice"
    ]
};
const standard = {
    "audio/aac": [
        "aac"
    ],
    "application/andrew-inset": [
        "ez"
    ],
    "application/applixware": [
        "aw"
    ],
    "application/atom+xml": [
        "atom"
    ],
    "application/atomcat+xml": [
        "atomcat"
    ],
    "application/atomdeleted+xml": [
        "atomdeleted"
    ],
    "application/atomsvc+xml": [
        "atomsvc"
    ],
    "application/atsc-dwd+xml": [
        "dwd"
    ],
    "application/atsc-held+xml": [
        "held"
    ],
    "application/atsc-rsat+xml": [
        "rsat"
    ],
    "application/bdoc": [
        "bdoc"
    ],
    "application/calendar+xml": [
        "xcs"
    ],
    "application/ccxml+xml": [
        "ccxml"
    ],
    "application/cdfx+xml": [
        "cdfx"
    ],
    "application/cdmi-capability": [
        "cdmia"
    ],
    "application/cdmi-container": [
        "cdmic"
    ],
    "application/cdmi-domain": [
        "cdmid"
    ],
    "application/cdmi-object": [
        "cdmio"
    ],
    "application/cdmi-queue": [
        "cdmiq"
    ],
    "application/cu-seeme": [
        "cu"
    ],
    "application/dash+xml": [
        "mpd"
    ],
    "application/davmount+xml": [
        "davmount"
    ],
    "application/docbook+xml": [
        "dbk"
    ],
    "application/dssc+der": [
        "dssc"
    ],
    "application/dssc+xml": [
        "xdssc"
    ],
    "application/ecmascript": [
        "ecma",
        "es"
    ],
    "application/emma+xml": [
        "emma"
    ],
    "application/emotionml+xml": [
        "emotionml"
    ],
    "application/epub+zip": [
        "epub"
    ],
    "application/exi": [
        "exi"
    ],
    "application/fdt+xml": [
        "fdt"
    ],
    "application/font-tdpfr": [
        "pfr"
    ],
    "application/geo+json": [
        "geojson"
    ],
    "application/gml+xml": [
        "gml"
    ],
    "application/gpx+xml": [
        "gpx"
    ],
    "application/gxf": [
        "gxf"
    ],
    "application/gzip": [
        "gz"
    ],
    "application/hjson": [
        "hjson"
    ],
    "application/hyperstudio": [
        "stk"
    ],
    "application/inkml+xml": [
        "ink",
        "inkml"
    ],
    "application/ipfix": [
        "ipfix"
    ],
    "application/its+xml": [
        "its"
    ],
    "application/java-archive": [
        "jar",
        "war",
        "ear"
    ],
    "application/java-serialized-object": [
        "ser"
    ],
    "application/java-vm": [
        "class"
    ],
    "application/javascript": [
        "js",
        "mjs"
    ],
    "application/json": [
        "json",
        "map"
    ],
    "application/json5": [
        "json5"
    ],
    "application/jsonml+json": [
        "jsonml"
    ],
    "application/ld+json": [
        "jsonld"
    ],
    "application/lgr+xml": [
        "lgr"
    ],
    "application/lost+xml": [
        "lostxml"
    ],
    "application/mac-binhex40": [
        "hqx"
    ],
    "application/mac-compactpro": [
        "cpt"
    ],
    "application/mads+xml": [
        "mads"
    ],
    "application/manifest+json": [
        "webmanifest"
    ],
    "application/marc": [
        "mrc"
    ],
    "application/marcxml+xml": [
        "mrcx"
    ],
    "application/mathematica": [
        "ma",
        "nb",
        "mb"
    ],
    "application/mathml+xml": [
        "mathml"
    ],
    "application/mbox": [
        "mbox"
    ],
    "application/mediaservercontrol+xml": [
        "mscml"
    ],
    "application/metalink+xml": [
        "metalink"
    ],
    "application/metalink4+xml": [
        "meta4"
    ],
    "application/mets+xml": [
        "mets"
    ],
    "application/mmt-aei+xml": [
        "maei"
    ],
    "application/mmt-usd+xml": [
        "musd"
    ],
    "application/mods+xml": [
        "mods"
    ],
    "application/mp21": [
        "m21",
        "mp21"
    ],
    "application/mp4": [
        "mp4s",
        "m4p"
    ],
    "application/mrb-consumer+xml": [
        "*xdf"
    ],
    "application/mrb-publish+xml": [
        "*xdf"
    ],
    "application/msword": [
        "doc",
        "dot"
    ],
    "application/mxf": [
        "mxf"
    ],
    "application/n-quads": [
        "nq"
    ],
    "application/n-triples": [
        "nt"
    ],
    "application/node": [
        "cjs"
    ],
    "application/octet-stream": [
        "bin",
        "dms",
        "lrf",
        "mar",
        "so",
        "dist",
        "distz",
        "pkg",
        "bpk",
        "dump",
        "elc",
        "deploy",
        "exe",
        "dll",
        "deb",
        "dmg",
        "iso",
        "img",
        "msi",
        "msp",
        "msm",
        "buffer"
    ],
    "application/oda": [
        "oda"
    ],
    "application/oebps-package+xml": [
        "opf"
    ],
    "application/ogg": [
        "ogx"
    ],
    "application/omdoc+xml": [
        "omdoc"
    ],
    "application/onenote": [
        "onetoc",
        "onetoc2",
        "onetmp",
        "onepkg"
    ],
    "application/oxps": [
        "oxps"
    ],
    "application/p2p-overlay+xml": [
        "relo"
    ],
    "application/patch-ops-error+xml": [
        "*xer"
    ],
    "application/pdf": [
        "pdf"
    ],
    "application/pgp-encrypted": [
        "pgp"
    ],
    "application/pgp-signature": [
        "asc",
        "sig"
    ],
    "application/pics-rules": [
        "prf"
    ],
    "application/pkcs10": [
        "p10"
    ],
    "application/pkcs7-mime": [
        "p7m",
        "p7c"
    ],
    "application/pkcs7-signature": [
        "p7s"
    ],
    "application/pkcs8": [
        "p8"
    ],
    "application/pkix-attr-cert": [
        "ac"
    ],
    "application/pkix-cert": [
        "cer"
    ],
    "application/pkix-crl": [
        "crl"
    ],
    "application/pkix-pkipath": [
        "pkipath"
    ],
    "application/pkixcmp": [
        "pki"
    ],
    "application/pls+xml": [
        "pls"
    ],
    "application/postscript": [
        "ai",
        "eps",
        "ps"
    ],
    "application/provenance+xml": [
        "provx"
    ],
    "application/pskc+xml": [
        "pskcxml"
    ],
    "application/raml+yaml": [
        "raml"
    ],
    "application/rdf+xml": [
        "rdf",
        "owl"
    ],
    "application/reginfo+xml": [
        "rif"
    ],
    "application/relax-ng-compact-syntax": [
        "rnc"
    ],
    "application/resource-lists+xml": [
        "rl"
    ],
    "application/resource-lists-diff+xml": [
        "rld"
    ],
    "application/rls-services+xml": [
        "rs"
    ],
    "application/route-apd+xml": [
        "rapd"
    ],
    "application/route-s-tsid+xml": [
        "sls"
    ],
    "application/route-usd+xml": [
        "rusd"
    ],
    "application/rpki-ghostbusters": [
        "gbr"
    ],
    "application/rpki-manifest": [
        "mft"
    ],
    "application/rpki-roa": [
        "roa"
    ],
    "application/rsd+xml": [
        "rsd"
    ],
    "application/rss+xml": [
        "rss"
    ],
    "application/rtf": [
        "rtf"
    ],
    "application/sbml+xml": [
        "sbml"
    ],
    "application/scvp-cv-request": [
        "scq"
    ],
    "application/scvp-cv-response": [
        "scs"
    ],
    "application/scvp-vp-request": [
        "spq"
    ],
    "application/scvp-vp-response": [
        "spp"
    ],
    "application/sdp": [
        "sdp"
    ],
    "application/senml+xml": [
        "senmlx"
    ],
    "application/sensml+xml": [
        "sensmlx"
    ],
    "application/set-payment-initiation": [
        "setpay"
    ],
    "application/set-registration-initiation": [
        "setreg"
    ],
    "application/shf+xml": [
        "shf"
    ],
    "application/sieve": [
        "siv",
        "sieve"
    ],
    "application/smil+xml": [
        "smi",
        "smil"
    ],
    "application/sparql-query": [
        "rq"
    ],
    "application/sparql-results+xml": [
        "srx"
    ],
    "application/srgs": [
        "gram"
    ],
    "application/srgs+xml": [
        "grxml"
    ],
    "application/sru+xml": [
        "sru"
    ],
    "application/ssdl+xml": [
        "ssdl"
    ],
    "application/ssml+xml": [
        "ssml"
    ],
    "application/swid+xml": [
        "swidtag"
    ],
    "application/tei+xml": [
        "tei",
        "teicorpus"
    ],
    "application/thraud+xml": [
        "tfi"
    ],
    "application/timestamped-data": [
        "tsd"
    ],
    "application/toml": [
        "toml"
    ],
    "application/ttml+xml": [
        "ttml"
    ],
    "application/ubjson": [
        "ubj"
    ],
    "application/urc-ressheet+xml": [
        "rsheet"
    ],
    "application/urc-targetdesc+xml": [
        "td"
    ],
    "application/voicexml+xml": [
        "vxml"
    ],
    "application/wasm": [
        "wasm"
    ],
    "application/widget": [
        "wgt"
    ],
    "application/winhlp": [
        "hlp"
    ],
    "application/wsdl+xml": [
        "wsdl"
    ],
    "application/wspolicy+xml": [
        "wspolicy"
    ],
    "application/xaml+xml": [
        "xaml"
    ],
    "application/xcap-att+xml": [
        "xav"
    ],
    "application/xcap-caps+xml": [
        "xca"
    ],
    "application/xcap-diff+xml": [
        "xdf"
    ],
    "application/xcap-el+xml": [
        "xel"
    ],
    "application/xcap-error+xml": [
        "xer"
    ],
    "application/xcap-ns+xml": [
        "xns"
    ],
    "application/xenc+xml": [
        "xenc"
    ],
    "application/xhtml+xml": [
        "xhtml",
        "xht"
    ],
    "application/xliff+xml": [
        "xlf"
    ],
    "application/xml": [
        "xml",
        "xsl",
        "xsd",
        "rng"
    ],
    "application/xml-dtd": [
        "dtd"
    ],
    "application/xop+xml": [
        "xop"
    ],
    "application/xproc+xml": [
        "xpl"
    ],
    "application/xslt+xml": [
        "*xsl",
        "xslt"
    ],
    "application/xspf+xml": [
        "xspf"
    ],
    "application/xv+xml": [
        "mxml",
        "xhvml",
        "xvml",
        "xvm"
    ],
    "application/yang": [
        "yang"
    ],
    "application/yin+xml": [
        "yin"
    ],
    "application/zip": [
        "zip"
    ],
    "audio/3gpp": [
        "*3gpp"
    ],
    "audio/adpcm": [
        "adp"
    ],
    "audio/basic": [
        "au",
        "snd"
    ],
    "audio/midi": [
        "mid",
        "midi",
        "kar",
        "rmi"
    ],
    "audio/mobile-xmf": [
        "mxmf"
    ],
    "audio/mp3": [
        "*mp3"
    ],
    "audio/mp4": [
        "m4a",
        "mp4a"
    ],
    "audio/mpeg": [
        "mpga",
        "mp2",
        "mp2a",
        "mp3",
        "m2a",
        "m3a"
    ],
    "audio/ogg": [
        "oga",
        "ogg",
        "spx"
    ],
    "audio/s3m": [
        "s3m"
    ],
    "audio/silk": [
        "sil"
    ],
    "audio/wav": [
        "wav"
    ],
    "audio/wave": [
        "*wav"
    ],
    "audio/webm": [
        "weba"
    ],
    "audio/xm": [
        "xm"
    ],
    "font/collection": [
        "ttc"
    ],
    "font/otf": [
        "otf"
    ],
    "font/ttf": [
        "ttf"
    ],
    "font/woff": [
        "woff"
    ],
    "font/woff2": [
        "woff2"
    ],
    "image/aces": [
        "exr"
    ],
    "image/apng": [
        "apng"
    ],
    "image/avif": [
        "avif"
    ],
    "image/bmp": [
        "bmp"
    ],
    "image/cgm": [
        "cgm"
    ],
    "image/dicom-rle": [
        "drle"
    ],
    "image/emf": [
        "emf"
    ],
    "image/fits": [
        "fits"
    ],
    "image/g3fax": [
        "g3"
    ],
    "image/gif": [
        "gif"
    ],
    "image/heic": [
        "heic"
    ],
    "image/heic-sequence": [
        "heics"
    ],
    "image/heif": [
        "heif"
    ],
    "image/heif-sequence": [
        "heifs"
    ],
    "image/hej2k": [
        "hej2"
    ],
    "image/hsj2": [
        "hsj2"
    ],
    "image/ief": [
        "ief"
    ],
    "image/jls": [
        "jls"
    ],
    "image/jp2": [
        "jp2",
        "jpg2"
    ],
    "image/jpeg": [
        "jpeg",
        "jpg",
        "jpe"
    ],
    "image/jph": [
        "jph"
    ],
    "image/jphc": [
        "jhc"
    ],
    "image/jpm": [
        "jpm"
    ],
    "image/jpx": [
        "jpx",
        "jpf"
    ],
    "image/jxr": [
        "jxr"
    ],
    "image/jxra": [
        "jxra"
    ],
    "image/jxrs": [
        "jxrs"
    ],
    "image/jxs": [
        "jxs"
    ],
    "image/jxsc": [
        "jxsc"
    ],
    "image/jxsi": [
        "jxsi"
    ],
    "image/jxss": [
        "jxss"
    ],
    "image/ktx": [
        "ktx"
    ],
    "image/ktx2": [
        "ktx2"
    ],
    "image/png": [
        "png"
    ],
    "image/sgi": [
        "sgi"
    ],
    "image/svg+xml": [
        "svg",
        "svgz"
    ],
    "image/t38": [
        "t38"
    ],
    "image/tiff": [
        "tif",
        "tiff"
    ],
    "image/tiff-fx": [
        "tfx"
    ],
    "image/webp": [
        "webp"
    ],
    "image/wmf": [
        "wmf"
    ],
    "message/disposition-notification": [
        "disposition-notification"
    ],
    "message/global": [
        "u8msg"
    ],
    "message/global-delivery-status": [
        "u8dsn"
    ],
    "message/global-disposition-notification": [
        "u8mdn"
    ],
    "message/global-headers": [
        "u8hdr"
    ],
    "message/rfc822": [
        "eml",
        "mime"
    ],
    "model/3mf": [
        "3mf"
    ],
    "model/gltf+json": [
        "gltf"
    ],
    "model/gltf-binary": [
        "glb"
    ],
    "model/iges": [
        "igs",
        "iges"
    ],
    "model/mesh": [
        "msh",
        "mesh",
        "silo"
    ],
    "model/mtl": [
        "mtl"
    ],
    "model/obj": [
        "obj"
    ],
    "model/stl": [
        "stl"
    ],
    "model/vrml": [
        "wrl",
        "vrml"
    ],
    "model/x3d+binary": [
        "*x3db",
        "x3dbz"
    ],
    "model/x3d+fastinfoset": [
        "x3db"
    ],
    "model/x3d+vrml": [
        "*x3dv",
        "x3dvz"
    ],
    "model/x3d+xml": [
        "x3d",
        "x3dz"
    ],
    "model/x3d-vrml": [
        "x3dv"
    ],
    "text/cache-manifest": [
        "appcache",
        "manifest"
    ],
    "text/calendar": [
        "ics",
        "ifb"
    ],
    "text/coffeescript": [
        "coffee",
        "litcoffee"
    ],
    "text/css": [
        "css"
    ],
    "text/csv": [
        "csv"
    ],
    "text/html": [
        "html",
        "htm",
        "shtml"
    ],
    "text/jade": [
        "jade"
    ],
    "text/jsx": [
        "jsx"
    ],
    "text/less": [
        "less"
    ],
    "text/markdown": [
        "markdown",
        "md"
    ],
    "text/mathml": [
        "mml"
    ],
    "text/mdx": [
        "mdx"
    ],
    "text/n3": [
        "n3"
    ],
    "text/plain": [
        "txt",
        "text",
        "conf",
        "def",
        "list",
        "log",
        "in",
        "ini"
    ],
    "text/richtext": [
        "rtx"
    ],
    "text/rtf": [
        "*rtf"
    ],
    "text/sgml": [
        "sgml",
        "sgm"
    ],
    "text/shex": [
        "shex"
    ],
    "text/slim": [
        "slim",
        "slm"
    ],
    "text/spdx": [
        "spdx"
    ],
    "text/stylus": [
        "stylus",
        "styl"
    ],
    "text/tab-separated-values": [
        "tsv"
    ],
    "text/troff": [
        "t",
        "tr",
        "roff",
        "man",
        "me",
        "ms"
    ],
    "text/turtle": [
        "ttl"
    ],
    "text/uri-list": [
        "uri",
        "uris",
        "urls"
    ],
    "text/vcard": [
        "vcard"
    ],
    "text/vtt": [
        "vtt"
    ],
    "text/xml": [
        "*xml"
    ],
    "text/yaml": [
        "yaml",
        "yml"
    ],
    "video/3gpp": [
        "3gp",
        "3gpp"
    ],
    "video/3gpp2": [
        "3g2"
    ],
    "video/h261": [
        "h261"
    ],
    "video/h263": [
        "h263"
    ],
    "video/h264": [
        "h264"
    ],
    "video/jpeg": [
        "jpgv"
    ],
    "video/jpm": [
        "*jpm",
        "jpgm"
    ],
    "video/mj2": [
        "mj2",
        "mjp2"
    ],
    "video/mp2t": [
        "ts"
    ],
    "video/mp4": [
        "mp4",
        "mp4v",
        "mpg4"
    ],
    "video/mpeg": [
        "mpeg",
        "mpg",
        "mpe",
        "m1v",
        "m2v"
    ],
    "video/ogg": [
        "ogv"
    ],
    "video/quicktime": [
        "qt",
        "mov"
    ],
    "video/webm": [
        "webm"
    ]
};
class Mime {
    types = new Map();
    extensions = new Map();
    constructor(...typeMaps){
        for (var typeMap of typeMaps){
            this.define(typeMap);
        }
    }
    define(typeMap, force) {
        for(var type in typeMap){
            let extensions = typeMap[type].map(function(t) {
                return t.toLowerCase();
            });
            type = type.toLowerCase();
            for(var i = 0; i < extensions.length; i++){
                var ext = extensions[i];
                if (ext[0] == '*') {
                    continue;
                }
                if (!force && this.types.has(ext)) {
                    throw new Error('Attempt to change mapping for "' + ext + '" extension from "' + this.types.get(ext) + '" to "' + type + '". Pass `force=true` to allow this, otherwise remove "' + ext + '" from the list of extensions for "' + type + '".');
                }
                this.types.set(ext, type);
            }
            if (force || !this.extensions.has(type)) {
                let ext = extensions[0];
                this.extensions.set(type, ext[0] != '*' ? ext : ext.substr(1));
            }
        }
    }
    getType(path) {
        let last = path.replace(/^.*[/\\]/, '').toLowerCase();
        let ext = last.replace(/^.*\./, '').toLowerCase();
        let hasPath = last.length < path.length;
        let hasDot = ext.length < last.length - 1;
        return (hasDot || !hasPath) && this.types.has(ext) ? this.types.get(ext) : undefined;
    }
    getExtension(type) {
        let match = type.match(/^\s*([^;\s]*)/);
        return match && match[1] && this.extensions.has(match[1]) ? this.extensions.get(match[1].toLowerCase()) : undefined;
    }
}
new Mime(standard);
const mime = new Mime(standard, other);
class AssertionError extends Error {
    name = "AssertionError";
    constructor(message){
        super(message);
    }
}
function assert4(expr, msg = "") {
    if (!expr) {
        throw new AssertionError(msg);
    }
}
const osType2 = (()=>{
    const { Deno: Deno1 } = globalThis;
    if (typeof Deno1?.build?.os === "string") {
        return Deno1.build.os;
    }
    const { navigator } = globalThis;
    if (navigator?.appVersion?.includes?.("Win")) {
        return "windows";
    }
    return "linux";
})();
const isWindows2 = osType2 === "windows";
const CHAR_FORWARD_SLASH2 = 47;
function assertPath2(path) {
    if (typeof path !== "string") {
        throw new TypeError(`Path must be a string. Received ${JSON.stringify(path)}`);
    }
}
function isPosixPathSeparator2(code) {
    return code === 47;
}
function isPathSeparator2(code) {
    return isPosixPathSeparator2(code) || code === 92;
}
function isWindowsDeviceRoot2(code) {
    return code >= 97 && code <= 122 || code >= 65 && code <= 90;
}
function normalizeString2(path, allowAboveRoot, separator, isPathSeparator) {
    let res = "";
    let lastSegmentLength = 0;
    let lastSlash = -1;
    let dots = 0;
    let code;
    for(let i = 0, len = path.length; i <= len; ++i){
        if (i < len) code = path.charCodeAt(i);
        else if (isPathSeparator(code)) break;
        else code = CHAR_FORWARD_SLASH2;
        if (isPathSeparator(code)) {
            if (lastSlash === i - 1 || dots === 1) {} else if (lastSlash !== i - 1 && dots === 2) {
                if (res.length < 2 || lastSegmentLength !== 2 || res.charCodeAt(res.length - 1) !== 46 || res.charCodeAt(res.length - 2) !== 46) {
                    if (res.length > 2) {
                        const lastSlashIndex = res.lastIndexOf(separator);
                        if (lastSlashIndex === -1) {
                            res = "";
                            lastSegmentLength = 0;
                        } else {
                            res = res.slice(0, lastSlashIndex);
                            lastSegmentLength = res.length - 1 - res.lastIndexOf(separator);
                        }
                        lastSlash = i;
                        dots = 0;
                        continue;
                    } else if (res.length === 2 || res.length === 1) {
                        res = "";
                        lastSegmentLength = 0;
                        lastSlash = i;
                        dots = 0;
                        continue;
                    }
                }
                if (allowAboveRoot) {
                    if (res.length > 0) res += `${separator}..`;
                    else res = "..";
                    lastSegmentLength = 2;
                }
            } else {
                if (res.length > 0) res += separator + path.slice(lastSlash + 1, i);
                else res = path.slice(lastSlash + 1, i);
                lastSegmentLength = i - lastSlash - 1;
            }
            lastSlash = i;
            dots = 0;
        } else if (code === 46 && dots !== -1) {
            ++dots;
        } else {
            dots = -1;
        }
    }
    return res;
}
function stripTrailingSeparators2(segment, isSep) {
    if (segment.length <= 1) {
        return segment;
    }
    let end = segment.length;
    for(let i = segment.length - 1; i > 0; i--){
        if (isSep(segment.charCodeAt(i))) {
            end = i;
        } else {
            break;
        }
    }
    return segment.slice(0, end);
}
function posixResolve(...pathSegments) {
    let resolvedPath = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1 && !resolvedAbsolute; i--){
        let path;
        if (i >= 0) path = pathSegments[i];
        else {
            const { Deno: Deno1 } = globalThis;
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
        }
        assertPath2(path);
        if (path.length === 0) {
            continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute = isPosixPathSeparator2(path.charCodeAt(0));
    }
    resolvedPath = normalizeString2(resolvedPath, !resolvedAbsolute, "/", isPosixPathSeparator2);
    if (resolvedAbsolute) {
        if (resolvedPath.length > 0) return `/${resolvedPath}`;
        else return "/";
    } else if (resolvedPath.length > 0) return resolvedPath;
    else return ".";
}
function windowsResolve(...pathSegments) {
    let resolvedDevice = "";
    let resolvedTail = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1; i--){
        let path;
        const { Deno: Deno1 } = globalThis;
        if (i >= 0) {
            path = pathSegments[i];
        } else if (!resolvedDevice) {
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a drive-letter-less path without a CWD.");
            }
            path = Deno1.cwd();
        } else {
            if (typeof Deno1?.env?.get !== "function" || typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
            if (path === undefined || path.slice(0, 3).toLowerCase() !== `${resolvedDevice.toLowerCase()}\\`) {
                path = `${resolvedDevice}\\`;
            }
        }
        assertPath2(path);
        const len = path.length;
        if (len === 0) continue;
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator2(code)) {
                isAbsolute = true;
                if (isPathSeparator2(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator2(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        const firstPart = path.slice(last, j);
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator2(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator2(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                device = `\\\\${firstPart}\\${path.slice(last)}`;
                                rootEnd = j;
                            } else if (j !== last) {
                                device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                                rootEnd = j;
                            }
                        }
                    }
                } else {
                    rootEnd = 1;
                }
            } else if (isWindowsDeviceRoot2(code)) {
                if (path.charCodeAt(1) === 58) {
                    device = path.slice(0, 2);
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator2(path.charCodeAt(2))) {
                            isAbsolute = true;
                            rootEnd = 3;
                        }
                    }
                }
            }
        } else if (isPathSeparator2(code)) {
            rootEnd = 1;
            isAbsolute = true;
        }
        if (device.length > 0 && resolvedDevice.length > 0 && device.toLowerCase() !== resolvedDevice.toLowerCase()) {
            continue;
        }
        if (resolvedDevice.length === 0 && device.length > 0) {
            resolvedDevice = device;
        }
        if (!resolvedAbsolute) {
            resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
            resolvedAbsolute = isAbsolute;
        }
        if (resolvedAbsolute && resolvedDevice.length > 0) break;
    }
    resolvedTail = normalizeString2(resolvedTail, !resolvedAbsolute, "\\", isPathSeparator2);
    return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail || ".";
}
function assertArg(path) {
    assertPath2(path);
    if (path.length === 0) return ".";
}
function posixNormalize(path) {
    assertArg(path);
    const isAbsolute = isPosixPathSeparator2(path.charCodeAt(0));
    const trailingSeparator = isPosixPathSeparator2(path.charCodeAt(path.length - 1));
    path = normalizeString2(path, !isAbsolute, "/", isPosixPathSeparator2);
    if (path.length === 0 && !isAbsolute) path = ".";
    if (path.length > 0 && trailingSeparator) path += "/";
    if (isAbsolute) return `/${path}`;
    return path;
}
function windowsNormalize(path) {
    assertArg(path);
    const len = path.length;
    let rootEnd = 0;
    let device;
    let isAbsolute = false;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator2(code)) {
            isAbsolute = true;
            if (isPathSeparator2(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator2(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    const firstPart = path.slice(last, j);
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator2(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator2(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return `\\\\${firstPart}\\${path.slice(last)}\\`;
                        } else if (j !== last) {
                            device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                            rootEnd = j;
                        }
                    }
                }
            } else {
                rootEnd = 1;
            }
        } else if (isWindowsDeviceRoot2(code)) {
            if (path.charCodeAt(1) === 58) {
                device = path.slice(0, 2);
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator2(path.charCodeAt(2))) {
                        isAbsolute = true;
                        rootEnd = 3;
                    }
                }
            }
        }
    } else if (isPathSeparator2(code)) {
        return "\\";
    }
    let tail;
    if (rootEnd < len) {
        tail = normalizeString2(path.slice(rootEnd), !isAbsolute, "\\", isPathSeparator2);
    } else {
        tail = "";
    }
    if (tail.length === 0 && !isAbsolute) tail = ".";
    if (tail.length > 0 && isPathSeparator2(path.charCodeAt(len - 1))) {
        tail += "\\";
    }
    if (device === undefined) {
        if (isAbsolute) {
            if (tail.length > 0) return `\\${tail}`;
            else return "\\";
        } else if (tail.length > 0) {
            return tail;
        } else {
            return "";
        }
    } else if (isAbsolute) {
        if (tail.length > 0) return `${device}\\${tail}`;
        else return `${device}\\`;
    } else if (tail.length > 0) {
        return device + tail;
    } else {
        return device;
    }
}
function windowsIsAbsolute(path) {
    assertPath2(path);
    const len = path.length;
    if (len === 0) return false;
    const code = path.charCodeAt(0);
    if (isPathSeparator2(code)) {
        return true;
    } else if (isWindowsDeviceRoot2(code)) {
        if (len > 2 && path.charCodeAt(1) === 58) {
            if (isPathSeparator2(path.charCodeAt(2))) return true;
        }
    }
    return false;
}
function posixIsAbsolute(path) {
    assertPath2(path);
    return path.length > 0 && isPosixPathSeparator2(path.charCodeAt(0));
}
function posixJoin(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    for(let i = 0, len = paths.length; i < len; ++i){
        const path = paths[i];
        assertPath2(path);
        if (path.length > 0) {
            if (!joined) joined = path;
            else joined += `/${path}`;
        }
    }
    if (!joined) return ".";
    return posixNormalize(joined);
}
function windowsJoin(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    let firstPart = null;
    for(let i = 0; i < paths.length; ++i){
        const path = paths[i];
        assertPath2(path);
        if (path.length > 0) {
            if (joined === undefined) joined = firstPart = path;
            else joined += `\\${path}`;
        }
    }
    if (joined === undefined) return ".";
    let needsReplace = true;
    let slashCount = 0;
    assert4(firstPart != null);
    if (isPathSeparator2(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
            if (isPathSeparator2(firstPart.charCodeAt(1))) {
                ++slashCount;
                if (firstLen > 2) {
                    if (isPathSeparator2(firstPart.charCodeAt(2))) ++slashCount;
                    else {
                        needsReplace = false;
                    }
                }
            }
        }
    }
    if (needsReplace) {
        for(; slashCount < joined.length; ++slashCount){
            if (!isPathSeparator2(joined.charCodeAt(slashCount))) break;
        }
        if (slashCount >= 2) joined = `\\${joined.slice(slashCount)}`;
    }
    return windowsNormalize(joined);
}
function assertArgs(from, to) {
    assertPath2(from);
    assertPath2(to);
    if (from === to) return "";
}
function posixRelative(from, to) {
    assertArgs(from, to);
    from = posixResolve(from);
    to = posixResolve(to);
    if (from === to) return "";
    let fromStart = 1;
    const fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (!isPosixPathSeparator2(from.charCodeAt(fromStart))) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 1;
    const toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (!isPosixPathSeparator2(to.charCodeAt(toStart))) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (isPosixPathSeparator2(to.charCodeAt(toStart + i))) {
                    return to.slice(toStart + i + 1);
                } else if (i === 0) {
                    return to.slice(toStart + i);
                }
            } else if (fromLen > length) {
                if (isPosixPathSeparator2(from.charCodeAt(fromStart + i))) {
                    lastCommonSep = i;
                } else if (i === 0) {
                    lastCommonSep = 0;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (isPosixPathSeparator2(fromCode)) lastCommonSep = i;
    }
    let out = "";
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || isPosixPathSeparator2(from.charCodeAt(i))) {
            if (out.length === 0) out += "..";
            else out += "/..";
        }
    }
    if (out.length > 0) return out + to.slice(toStart + lastCommonSep);
    else {
        toStart += lastCommonSep;
        if (isPosixPathSeparator2(to.charCodeAt(toStart))) ++toStart;
        return to.slice(toStart);
    }
}
function windowsRelative(from, to) {
    assertArgs(from, to);
    const fromOrig = windowsResolve(from);
    const toOrig = windowsResolve(to);
    if (fromOrig === toOrig) return "";
    from = fromOrig.toLowerCase();
    to = toOrig.toLowerCase();
    if (from === to) return "";
    let fromStart = 0;
    let fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (from.charCodeAt(fromStart) !== 92) break;
    }
    for(; fromEnd - 1 > fromStart; --fromEnd){
        if (from.charCodeAt(fromEnd - 1) !== 92) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 0;
    let toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (to.charCodeAt(toStart) !== 92) break;
    }
    for(; toEnd - 1 > toStart; --toEnd){
        if (to.charCodeAt(toEnd - 1) !== 92) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (to.charCodeAt(toStart + i) === 92) {
                    return toOrig.slice(toStart + i + 1);
                } else if (i === 2) {
                    return toOrig.slice(toStart + i);
                }
            }
            if (fromLen > length) {
                if (from.charCodeAt(fromStart + i) === 92) {
                    lastCommonSep = i;
                } else if (i === 2) {
                    lastCommonSep = 3;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (fromCode === 92) lastCommonSep = i;
    }
    if (i !== length && lastCommonSep === -1) {
        return toOrig;
    }
    let out = "";
    if (lastCommonSep === -1) lastCommonSep = 0;
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || from.charCodeAt(i) === 92) {
            if (out.length === 0) out += "..";
            else out += "\\..";
        }
    }
    if (out.length > 0) {
        return out + toOrig.slice(toStart + lastCommonSep, toEnd);
    } else {
        toStart += lastCommonSep;
        if (toOrig.charCodeAt(toStart) === 92) ++toStart;
        return toOrig.slice(toStart, toEnd);
    }
}
function posixToNamespacedPath(path) {
    return path;
}
function windowsToNamespacedPath(path) {
    if (typeof path !== "string") return path;
    if (path.length === 0) return "";
    const resolvedPath = windowsResolve(path);
    if (resolvedPath.length >= 3) {
        if (resolvedPath.charCodeAt(0) === 92) {
            if (resolvedPath.charCodeAt(1) === 92) {
                const code = resolvedPath.charCodeAt(2);
                if (code !== 63 && code !== 46) {
                    return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
                }
            }
        } else if (isWindowsDeviceRoot2(resolvedPath.charCodeAt(0))) {
            if (resolvedPath.charCodeAt(1) === 58 && resolvedPath.charCodeAt(2) === 92) {
                return `\\\\?\\${resolvedPath}`;
            }
        }
    }
    return path;
}
function assertArg1(path) {
    assertPath2(path);
    if (path.length === 0) return ".";
}
function posixDirname(path) {
    assertArg1(path);
    let end = -1;
    let matchedNonSeparator = false;
    for(let i = path.length - 1; i >= 1; --i){
        if (isPosixPathSeparator2(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                end = i;
                break;
            }
        } else {
            matchedNonSeparator = true;
        }
    }
    if (end === -1) {
        return isPosixPathSeparator2(path.charCodeAt(0)) ? "/" : ".";
    }
    return stripTrailingSeparators2(path.slice(0, end), isPosixPathSeparator2);
}
function windowsDirname(path) {
    assertArg1(path);
    const len = path.length;
    let rootEnd = -1;
    let end = -1;
    let matchedSlash = true;
    let offset = 0;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator2(code)) {
            rootEnd = offset = 1;
            if (isPathSeparator2(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator2(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator2(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator2(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return path;
                        }
                        if (j !== last) {
                            rootEnd = offset = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot2(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = offset = 2;
                if (len > 2) {
                    if (isPathSeparator2(path.charCodeAt(2))) rootEnd = offset = 3;
                }
            }
        }
    } else if (isPathSeparator2(code)) {
        return path;
    }
    for(let i = len - 1; i >= offset; --i){
        if (isPathSeparator2(path.charCodeAt(i))) {
            if (!matchedSlash) {
                end = i;
                break;
            }
        } else {
            matchedSlash = false;
        }
    }
    if (end === -1) {
        if (rootEnd === -1) return ".";
        else end = rootEnd;
    }
    return stripTrailingSeparators2(path.slice(0, end), isPosixPathSeparator2);
}
function stripSuffix2(name, suffix) {
    if (suffix.length >= name.length) {
        return name;
    }
    const lenDiff = name.length - suffix.length;
    for(let i = suffix.length - 1; i >= 0; --i){
        if (name.charCodeAt(lenDiff + i) !== suffix.charCodeAt(i)) {
            return name;
        }
    }
    return name.slice(0, -suffix.length);
}
function lastPathSegment2(path, isSep, start = 0) {
    let matchedNonSeparator = false;
    let end = path.length;
    for(let i = path.length - 1; i >= start; --i){
        if (isSep(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                start = i + 1;
                break;
            }
        } else if (!matchedNonSeparator) {
            matchedNonSeparator = true;
            end = i + 1;
        }
    }
    return path.slice(start, end);
}
function assertArgs1(path, suffix) {
    assertPath2(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
}
function posixBasename(path, suffix = "") {
    assertArgs1(path, suffix);
    const lastSegment = lastPathSegment2(path, isPosixPathSeparator2);
    const strippedSegment = stripTrailingSeparators2(lastSegment, isPosixPathSeparator2);
    return suffix ? stripSuffix2(strippedSegment, suffix) : strippedSegment;
}
function windowsBasename(path, suffix = "") {
    assertArgs1(path, suffix);
    let start = 0;
    if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (isWindowsDeviceRoot2(drive)) {
            if (path.charCodeAt(1) === 58) start = 2;
        }
    }
    const lastSegment = lastPathSegment2(path, isPathSeparator2, start);
    const strippedSegment = stripTrailingSeparators2(lastSegment, isPathSeparator2);
    return suffix ? stripSuffix2(strippedSegment, suffix) : strippedSegment;
}
function posixExtname(path) {
    assertPath2(path);
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    for(let i = path.length - 1; i >= 0; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator2(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function windowsExtname(path) {
    assertPath2(path);
    let start = 0;
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    if (path.length >= 2 && path.charCodeAt(1) === 58 && isWindowsDeviceRoot2(path.charCodeAt(0))) {
        start = startPart = 2;
    }
    for(let i = path.length - 1; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPathSeparator2(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function _format2(sep, pathObject) {
    const dir = pathObject.dir || pathObject.root;
    const base = pathObject.base || (pathObject.name || "") + (pathObject.ext || "");
    if (!dir) return base;
    if (base === sep) return dir;
    if (dir === pathObject.root) return dir + base;
    return dir + sep + base;
}
function assertArg2(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
}
function posixFormat(pathObject) {
    assertArg2(pathObject);
    return _format2("/", pathObject);
}
function windowsFormat(pathObject) {
    assertArg2(pathObject);
    return _format2("\\", pathObject);
}
function posixParse(path) {
    assertPath2(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    if (path.length === 0) return ret;
    const isAbsolute = isPosixPathSeparator2(path.charCodeAt(0));
    let start;
    if (isAbsolute) {
        ret.root = "/";
        start = 1;
    } else {
        start = 0;
    }
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator2(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            if (startPart === 0 && isAbsolute) {
                ret.base = ret.name = path.slice(1, end);
            } else {
                ret.base = ret.name = path.slice(startPart, end);
            }
        }
        ret.base = ret.base || "/";
    } else {
        if (startPart === 0 && isAbsolute) {
            ret.name = path.slice(1, startDot);
            ret.base = path.slice(1, end);
        } else {
            ret.name = path.slice(startPart, startDot);
            ret.base = path.slice(startPart, end);
        }
        ret.ext = path.slice(startDot, end);
    }
    if (startPart > 0) {
        ret.dir = stripTrailingSeparators2(path.slice(0, startPart - 1), isPosixPathSeparator2);
    } else if (isAbsolute) ret.dir = "/";
    return ret;
}
function windowsParse(path) {
    assertPath2(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    const len = path.length;
    if (len === 0) return ret;
    let rootEnd = 0;
    let code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator2(code)) {
            rootEnd = 1;
            if (isPathSeparator2(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator2(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator2(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator2(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            rootEnd = j;
                        } else if (j !== last) {
                            rootEnd = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot2(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator2(path.charCodeAt(2))) {
                        if (len === 3) {
                            ret.root = ret.dir = path;
                            ret.base = "\\";
                            return ret;
                        }
                        rootEnd = 3;
                    }
                } else {
                    ret.root = ret.dir = path;
                    return ret;
                }
            }
        }
    } else if (isPathSeparator2(code)) {
        ret.root = ret.dir = path;
        ret.base = "\\";
        return ret;
    }
    if (rootEnd > 0) ret.root = path.slice(0, rootEnd);
    let startDot = -1;
    let startPart = rootEnd;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= rootEnd; --i){
        code = path.charCodeAt(i);
        if (isPathSeparator2(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            ret.base = ret.name = path.slice(startPart, end);
        }
    } else {
        ret.name = path.slice(startPart, startDot);
        ret.base = path.slice(startPart, end);
        ret.ext = path.slice(startDot, end);
    }
    ret.base = ret.base || "\\";
    if (startPart > 0 && startPart !== rootEnd) {
        ret.dir = path.slice(0, startPart - 1);
    } else ret.dir = ret.root;
    return ret;
}
function assertArg3(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    return url;
}
function posixFromFileUrl(url) {
    url = assertArg3(url);
    return decodeURIComponent(url.pathname.replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
}
function windowsFromFileUrl(url) {
    url = assertArg3(url);
    let path = decodeURIComponent(url.pathname.replace(/\//g, "\\").replace(/%(?![0-9A-Fa-f]{2})/g, "%25")).replace(/^\\*([A-Za-z]:)(\\|$)/, "$1\\");
    if (url.hostname != "") {
        path = `\\\\${url.hostname}${path}`;
    }
    return path;
}
const WHITESPACE_ENCODINGS2 = {
    "\u0009": "%09",
    "\u000A": "%0A",
    "\u000B": "%0B",
    "\u000C": "%0C",
    "\u000D": "%0D",
    "\u0020": "%20"
};
function encodeWhitespace2(string) {
    return string.replaceAll(/[\s]/g, (c)=>{
        return WHITESPACE_ENCODINGS2[c] ?? c;
    });
}
function posixToFileUrl(path) {
    if (!posixIsAbsolute(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const url = new URL("file:///");
    url.pathname = encodeWhitespace2(path.replace(/%/g, "%25").replace(/\\/g, "%5C"));
    return url;
}
function windowsToFileUrl(path) {
    if (!windowsIsAbsolute(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const [, hostname, pathname] = path.match(/^(?:[/\\]{2}([^/\\]+)(?=[/\\](?:[^/\\]|$)))?(.*)/);
    const url = new URL("file:///");
    url.pathname = encodeWhitespace2(pathname.replace(/%/g, "%25"));
    if (hostname != null && hostname != "localhost") {
        url.hostname = hostname;
        if (!url.hostname) {
            throw new TypeError("Invalid hostname.");
        }
    }
    return url;
}
const sep5 = "\\";
const delimiter6 = ";";
const mod4 = {
    resolve: windowsResolve,
    normalize: windowsNormalize,
    isAbsolute: windowsIsAbsolute,
    join: windowsJoin,
    relative: windowsRelative,
    toNamespacedPath: windowsToNamespacedPath,
    dirname: windowsDirname,
    basename: windowsBasename,
    extname: windowsExtname,
    format: windowsFormat,
    parse: windowsParse,
    fromFileUrl: windowsFromFileUrl,
    toFileUrl: windowsToFileUrl,
    sep: sep5,
    delimiter: delimiter6
};
const sep6 = "/";
const delimiter7 = ":";
const mod5 = {
    resolve: posixResolve,
    normalize: posixNormalize,
    isAbsolute: posixIsAbsolute,
    join: posixJoin,
    relative: posixRelative,
    toNamespacedPath: posixToNamespacedPath,
    dirname: posixDirname,
    basename: posixBasename,
    extname: posixExtname,
    format: posixFormat,
    parse: posixParse,
    fromFileUrl: posixFromFileUrl,
    toFileUrl: posixToFileUrl,
    sep: sep6,
    delimiter: delimiter7
};
function basename6(path, suffix = "") {
    return isWindows2 ? windowsBasename(path, suffix) : posixBasename(path, suffix);
}
function fromFileUrl6(url) {
    return isWindows2 ? windowsFromFileUrl(url) : posixFromFileUrl(url);
}
function join8(...paths) {
    return isWindows2 ? windowsJoin(...paths) : posixJoin(...paths);
}
function normalize9(path) {
    return isWindows2 ? windowsNormalize(path) : posixNormalize(path);
}
const path4 = isWindows2 ? mod4 : mod5;
const { join: join9, normalize: normalize10 } = path4;
isWindows2 ? mod4.delimiter : mod5.delimiter;
async function createWalkEntry(path) {
    path = toPathString(path);
    path = normalize9(path);
    const name = basename6(path);
    const info = await Deno.stat(path);
    return {
        path,
        name,
        isFile: info.isFile,
        isDirectory: info.isDirectory,
        isSymlink: info.isSymlink
    };
}
function toPathString(pathUrl) {
    return pathUrl instanceof URL ? fromFileUrl6(pathUrl) : pathUrl;
}
class WalkError extends Error {
    cause;
    name = "WalkError";
    path;
    constructor(cause, path){
        super(`${cause instanceof Error ? cause.message : cause} for path "${path}"`);
        this.path = path;
        this.cause = cause;
    }
}
function include(path, exts, match, skip) {
    if (exts && !exts.some((ext)=>path.endsWith(ext))) {
        return false;
    }
    if (match && !match.some((pattern)=>!!path.match(pattern))) {
        return false;
    }
    if (skip && skip.some((pattern)=>!!path.match(pattern))) {
        return false;
    }
    return true;
}
function wrapErrorWithPath(err, root) {
    if (err instanceof WalkError) return err;
    return new WalkError(err, root);
}
async function* walk(root, { maxDepth = Infinity, includeFiles = true, includeDirs = true, includeSymlinks = true, followSymlinks = false, exts = undefined, match = undefined, skip = undefined } = {}) {
    if (maxDepth < 0) {
        return;
    }
    root = toPathString(root);
    if (includeDirs && include(root, exts, match, skip)) {
        yield await createWalkEntry(root);
    }
    if (maxDepth < 1 || !include(root, undefined, undefined, skip)) {
        return;
    }
    try {
        for await (const entry of Deno.readDir(root)){
            assert4(entry.name != null);
            let path = join8(root, entry.name);
            let { isSymlink, isDirectory } = entry;
            if (isSymlink) {
                if (!followSymlinks) {
                    if (includeSymlinks && include(path, exts, match, skip)) {
                        yield {
                            path,
                            ...entry
                        };
                    }
                    continue;
                }
                path = await Deno.realPath(path);
                ({ isSymlink, isDirectory } = await Deno.lstat(path));
            }
            if (isSymlink || isDirectory) {
                yield* walk(path, {
                    maxDepth: maxDepth - 1,
                    includeFiles,
                    includeDirs,
                    includeSymlinks,
                    followSymlinks,
                    exts,
                    match,
                    skip
                });
            } else if (includeFiles && include(path, exts, match, skip)) {
                yield {
                    path,
                    ...entry
                };
            }
        }
    } catch (err) {
        throw wrapErrorWithPath(err, normalize9(root));
    }
}
function lookupContentType(path) {
    return mime.getType(path) || "application/octet-stream";
}
function normalizeForwardSlashPath(path) {
    return path.replaceAll("\\", "/");
}
const excludedFiles = [
    "data.db",
    "data.db-journal",
    "sync.json"
];
class DiskSpacePrimitives {
    rootPath;
    constructor(rootPath){
        this.rootPath = Deno.realPathSync(rootPath);
    }
    safePath(p) {
        const realPath = resolve5(p);
        if (!realPath.startsWith(this.rootPath)) {
            throw Error(`Path ${p} is not in the space`);
        }
        return realPath;
    }
    filenameToPath(pageName) {
        return this.safePath(join7(this.rootPath, pageName));
    }
    pathToFilename(fullPath) {
        return fullPath.substring(this.rootPath.length + 1);
    }
    async readFile(name) {
        const localPath = this.filenameToPath(name);
        try {
            const s = await Deno.stat(localPath);
            const contentType = lookupContentType(name);
            const f = await Deno.open(localPath, {
                read: true
            });
            const data = await readAll1(f);
            Deno.close(f.rid);
            return {
                data,
                meta: {
                    name: name,
                    created: s.birthtime?.getTime() || s.mtime?.getTime() || 0,
                    lastModified: s.mtime?.getTime() || 0,
                    perm: "rw",
                    size: s.size,
                    contentType: contentType
                }
            };
        } catch  {
            throw Error("Not found");
        }
    }
    async writeFile(name, data, _selfUpdate, meta) {
        const localPath = this.filenameToPath(name);
        try {
            await Deno.mkdir(dirname5(localPath), {
                recursive: true
            });
            const file = await Deno.open(localPath, {
                write: true,
                create: true,
                truncate: true
            });
            await Deno.write(file.rid, data);
            if (meta?.lastModified) {
                await Deno.futime(file.rid, new Date(), new Date(meta.lastModified));
            }
            file.close();
            return this.getFileMeta(name);
        } catch (e) {
            console.error("Error while writing file", name, e);
            throw Error(`Could not write ${name}`);
        }
    }
    async getFileMeta(name) {
        const localPath = this.filenameToPath(name);
        try {
            const s = await Deno.stat(localPath);
            return {
                name: name,
                size: s.size,
                contentType: lookupContentType(name),
                created: s.birthtime?.getTime() || s.mtime?.getTime() || 0,
                lastModified: s.mtime?.getTime() || 0,
                perm: "rw"
            };
        } catch  {
            throw Error(`Could not get meta for ${name}`);
        }
    }
    async deleteFile(name) {
        const localPath = this.filenameToPath(name);
        await Deno.remove(localPath);
    }
    async fetchFileList() {
        const allFiles = [];
        for await (const file of walk(this.rootPath, {
            includeDirs: false,
            skip: [
                new RegExp(`^${escapeRegExp(this.rootPath)}.*\\/\\..+$`)
            ]
        })){
            const fullPath = file.path;
            try {
                const s = await Deno.stat(fullPath);
                const name = fullPath.substring(this.rootPath.length + 1);
                if (excludedFiles.includes(name)) {
                    continue;
                }
                allFiles.push({
                    name: normalizeForwardSlashPath(name),
                    created: s.birthtime?.getTime() || s.mtime?.getTime() || 0,
                    lastModified: s.mtime?.getTime() || 0,
                    contentType: mime.getType(fullPath) || "application/octet-stream",
                    size: s.size,
                    perm: "rw"
                });
            } catch (e) {
                if (e instanceof Deno.errors.NotFound) {} else {
                    console.error("Failed to stat", fullPath, e);
                }
            }
        }
        return allFiles;
    }
}
function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
class KvMetaSpacePrimitives {
    kv;
    callbacks;
    constructor(kv, callbacks){
        this.kv = kv;
        this.callbacks = callbacks;
    }
    async readFile(name) {
        const [data, [meta]] = await Promise.all([
            this.callbacks.readFile(name, this),
            this.kv.batchGet([
                [
                    name
                ]
            ])
        ]);
        return {
            data,
            meta: meta
        };
    }
    async writeFile(name, data, _selfUpdate, desiredMeta) {
        let meta;
        try {
            meta = await this.getFileMeta(name);
        } catch  {}
        if (!meta) {
            meta = {
                name,
                perm: "rw",
                created: Date.now(),
                contentType: mime.getType(name) || "application/octet-stream",
                lastModified: 0,
                size: 0
            };
        }
        meta = {
            ...meta,
            lastModified: desiredMeta?.lastModified || Date.now(),
            size: data.byteLength
        };
        await Promise.all([
            this.callbacks.writeFile(name, data, this),
            this.kv.batchSet([
                {
                    key: [
                        name
                    ],
                    value: meta
                }
            ])
        ]);
        return meta;
    }
    async deleteFile(name) {
        await Promise.all([
            this.callbacks.deleteFile(name, this),
            this.kv.batchDelete([
                [
                    name
                ]
            ])
        ]);
    }
    async fetchFileList() {
        const files = [];
        for await (const meta of this.kv.query({})){
            files.push(meta.value);
        }
        return files;
    }
    async getFileMeta(name) {
        const fileMeta = (await this.kv.batchGet([
            [
                name
            ]
        ]))[0];
        if (!fileMeta) {
            throw new Error("Not found");
        }
        return fileMeta;
    }
}
class PrefixedKvPrimitives {
    wrapped;
    prefix;
    constructor(wrapped, prefix){
        this.wrapped = wrapped;
        this.prefix = prefix;
    }
    batchGet(keys) {
        return this.wrapped.batchGet(keys.map((key)=>this.applyPrefix(key)));
    }
    batchSet(entries) {
        return this.wrapped.batchSet(entries.map(({ key, value })=>({
                key: this.applyPrefix(key),
                value
            })));
    }
    batchDelete(keys) {
        return this.wrapped.batchDelete(keys.map((key)=>this.applyPrefix(key)));
    }
    async *query(options) {
        for await (const result of this.wrapped.query({
            prefix: this.applyPrefix(options.prefix)
        })){
            yield {
                key: this.stripPrefix(result.key),
                value: result.value
            };
        }
    }
    close() {
        this.wrapped.close();
    }
    applyPrefix(key) {
        return [
            ...this.prefix,
            ...key ? key : []
        ];
    }
    stripPrefix(key) {
        return key.slice(this.prefix.length);
    }
}
class ChunkedKvStoreSpacePrimitives extends KvMetaSpacePrimitives {
    constructor(baseKv, chunkSize, metaPrefix = [
        "meta"
    ], contentPrefix = [
        "content"
    ]){
        super(new PrefixedKvPrimitives(baseKv, metaPrefix), {
            async readFile (name, spacePrimitives) {
                const meta = await spacePrimitives.getFileMeta(name);
                const concatenatedChunks = new Uint8Array(meta.size);
                let offset = 0;
                for await (const { value } of baseKv.query({
                    prefix: [
                        ...contentPrefix,
                        name
                    ]
                })){
                    concatenatedChunks.set(value, offset);
                    offset += value.length;
                }
                return concatenatedChunks;
            },
            async writeFile (name, data) {
                let chunkId = 0;
                for(let i = 0; i < data.byteLength; i += chunkSize){
                    const chunk = data.slice(i, i + chunkSize);
                    await baseKv.batchSet([
                        {
                            key: [
                                ...contentPrefix,
                                name,
                                String(chunkId).padStart(3, "0")
                            ],
                            value: chunk
                        }
                    ]);
                    chunkId++;
                }
            },
            async deleteFile (name, spacePrimitives) {
                const fileMeta = await spacePrimitives.getFileMeta(name);
                const keysToDelete = [];
                let chunkId = 0;
                for(let i = 0; i < fileMeta.size; i += chunkSize){
                    keysToDelete.push([
                        ...contentPrefix,
                        name,
                        String(chunkId).padStart(3, "0")
                    ]);
                    chunkId++;
                }
                return baseKv.batchDelete(keysToDelete);
            }
        });
    }
}
const kvBatchSize = 100;
class DenoKvPrimitives {
    db;
    constructor(db){
        this.db = db;
    }
    async batchGet(keys) {
        const results = [];
        const batches = [];
        for(let i = 0; i < keys.length; i += kvBatchSize){
            batches.push(keys.slice(i, i + 100));
        }
        for (const batch of batches){
            const res = await this.db.getMany(batch);
            results.push(...res.map((r)=>r.value === null ? undefined : r.value));
        }
        return results;
    }
    async batchSet(entries) {
        const batches = [];
        for(let i = 0; i < entries.length; i += kvBatchSize){
            batches.push(entries.slice(i, i + 100));
        }
        for (const batch of batches){
            let batchOp = this.db.atomic();
            for (const { key, value } of batch){
                batchOp = batchOp.set(key, value);
            }
            const res = await batchOp.commit();
            if (!res.ok) {
                throw res;
            }
        }
    }
    async batchDelete(keys) {
        const batches = [];
        for(let i = 0; i < keys.length; i += kvBatchSize){
            batches.push(keys.slice(i, i + 100));
        }
        for (const batch of batches){
            let batchOp = this.db.atomic();
            for (const key of batch){
                batchOp = batchOp.delete(key);
            }
            const res = await batchOp.commit();
            if (!res.ok) {
                throw res;
            }
        }
    }
    async *query({ prefix }) {
        prefix = prefix || [];
        for await (const result of this.db.list({
            prefix: prefix
        })){
            yield {
                key: result.key,
                value: result.value
            };
        }
    }
    close() {
        this.db.close();
    }
}
await new Command().name("silverbullet-pub").description("SilverBullet Pub Server").help({
    colors: false
}).usage("<options> <folder>").arguments("[folder:string]").option("--hostname, -L <hostname:string>", "Hostname or address to listen on").option("-p, --port <port:number>", "Port to listen on").option("--token <token:string>", "Token").action(async (options, folder)=>{
    const hostname = options.hostname || Deno.env.get("SB_HOSTNAME") || "127.0.0.1";
    const port = options.port || Deno.env.get("SB_PORT") && +Deno.env.get("SB_PORT") || 8000;
    const token = options.token || Deno.env.get("SB_TOKEN");
    if (!token) {
        console.error("No token specified. Please pass a --token flag, or set SB_TOKEN environment variable.");
        Deno.exit(1);
    }
    let spacePrimitives;
    if (!folder) {
        folder = Deno.env.get("SB_FOLDER");
    }
    if (folder) {
        spacePrimitives = new DiskSpacePrimitives(folder);
    } else {
        let dbFile = Deno.env.get("SB_DB_FILE") || "pub.db";
        if (Deno.env.get("DENO_DEPLOYMENT_ID") !== undefined) {
            dbFile = undefined;
        }
        console.info("No folder specified. Using Deno KV mode. Storing data in", dbFile ? dbFile : "the default KV store");
        const kv = new DenoKvPrimitives(await Deno.openKv(dbFile));
        spacePrimitives = new ChunkedKvStoreSpacePrimitives(kv, 65536);
    }
    console.log("Going to start SilverBullet Pub Server binding to", `${hostname}:${port}`);
    const httpServer = new HttpServer1(spacePrimitives, {
        hostname,
        port,
        token,
        pagesPath: folder || "kv://"
    });
    httpServer.start();
}).parse(Deno.args);

