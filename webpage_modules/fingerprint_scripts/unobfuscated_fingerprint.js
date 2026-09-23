// ============ DEBUG CONFIGURATION ============
// Set to true to enable console logging (OFF by default)
const FINGERPRINT_DEBUG = false;

// Debug logging wrapper
function debugLog(...args) {
  if (FINGERPRINT_DEBUG) {
    console.log('[Fingerprint]', ...args);
  }
}

function debugWarn(...args) {
  if (FINGERPRINT_DEBUG) {
    console.warn('[Fingerprint]', ...args);
  }
}

function debugError(...args) {
  if (FINGERPRINT_DEBUG) {
    console.error('[Fingerprint]', ...args);
  }
}
// ============================================

class CompleteFingerprintSystem {
  constructor() {
    this.fingerprintComponents = {}
    this.additionalData = {}
  }

  // ============ SHA-512 via crypto.subtle ============
  async sha512(str) {
    const buf = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(str))
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  async collectAll() {
    await this.collectFingerprint()
    await this.collectAdditionalData()
    return {
      components: this.fingerprintComponents,
      additionalData: this.additionalData,
      timestamp: Date.now()
    }
  }

  // ============ PERSISTENT FINGERPRINT (HASHED) ============
  async collectFingerprint() {
    await this.add("canvas", () => this.getCanvasFingerprint())
    await this.add("webGlBasics", () => this.getWebGlBasics())
    await this.add("webGlExtensions", () => this.getWebGlExtensions())
    await this.add("webGl2Basics", () => this.getWebGl2Basics())
    await this.add("webGl2Extensions", () => this.getWebGl2Extensions())
    await this.add("audio", () => this.getAudioFingerprint())
    await this.add("audioContext", () => this.getAudioContextMetadata())
    await this.add("screenResolution", () => [screen?.width, screen?.height])
    await this.add("colorDepth", () => screen?.colorDepth)
    await this.add("pixelRatio", () => window.devicePixelRatio)
    await this.add("screenFrame", () => this.getScreenFrame())
    await this.add("screenExtended", () => this.getScreenExtended())
    await this.add("hdrSupport", () => this.detectHDR())
    await this.add("hardwareConcurrency", () => navigator.hardwareConcurrency)
    await this.add("deviceMemory", () => navigator.deviceMemory)
    await this.add("platform", () => navigator.platform)
    await this.add("userAgent", () => navigator.userAgent)
    await this.add("vendor", () => navigator.vendor)
    await this.add("plugins", () => this.getPlugins())
    await this.add("fonts", () => this.getFonts())
    await this.add("fontPreferences", () => this.getFontPreferences())
    await this.add("math", () => this.getMathFingerprint())
    await this.add("touchSupport", () => this.getTouchSupport())
    await this.add("canvasEmoji", () => this.getCanvasEmojiRendering())
    await this.add("hardwareInfo", () => this.getHardwareInfo())
    await this.add("browserInfo", () => this.getBrowserInfo())
    await this.add("heapInfo", () => this.getHeapInfo())
    await this.add("networkInfo", () => this.getNetworkInfo())
    await this.add("sensorSupport", () => this.getSensorSupport())
    await this.add("wasmSupport", () => this.getWasmSupport())
    await this.add("performanceFeatures", () => this.getPerformanceFeatures())

    // Hash canvas and canvasEmoji base64 data URIs down to SHA-512
    if (this.fingerprintComponents["canvas"] && this.fingerprintComponents["canvas"].value) {
      this.fingerprintComponents["canvas"].value = await this.sha512(this.fingerprintComponents["canvas"].value)
    }
    if (this.fingerprintComponents["canvasEmoji"] && this.fingerprintComponents["canvasEmoji"].value) {
      this.fingerprintComponents["canvasEmoji"].value = await this.sha512(this.fingerprintComponents["canvasEmoji"].value)
    }
  }

  async add(name, fn) {
    try {
      this.fingerprintComponents[name] = { value: await fn() }
    } catch (e) {
      this.fingerprintComponents[name] = { error: String(e.message) }
    }
  }

  // ============ ADDITIONAL DATA (NOT HASHED) ============
  async collectAdditionalData() {
    // Network info is added server-side
    this.additionalData.incognito = await this.detectIncognito()
    this.additionalData.vmDetection = await this.detectVM()
    this.additionalData.language = this.getLanguageInfo()
    this.additionalData.timezone = this.getTimezoneInfo()
    this.additionalData.permissions = await this.getPermissions()
    this.additionalData.battery = await this.getBatteryInfo()
    this.additionalData.cpuBenchmark = await this.runCPUBenchmark()
  }

  // ============ INCOGNITO DETECTION ============
  // Using detectIncognito library v1.3.6 (MIT License)
  // https://github.com/Joe12387/detectIncognito
  async detectIncognito() {
    try {
      // Execute the library code exactly as provided - it will attach to window.detectIncognito
      if (!window.detectIncognito) {
        eval(`!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define([],t):"object"==typeof exports?exports.detectIncognito=t():e.detectIncognito=t()}(this,function(){return function(){"use strict";var e={};return{598:function(e,t){var n=this&&this.__awaiter||function(e,t,n,r){return new(n||(n=Promise))(function(o,i){function a(e){try{u(r.next(e))}catch(e){i(e)}}function c(e){try{u(r.throw(e))}catch(e){i(e)}}function u(e){var t;e.done?o(e.value):(t=e.value,t instanceof n?t:new n(function(e){e(t)})).then(a,c)}u((r=r.apply(e,t||[])).next())})},r=this&&this.__generator||function(e,t){var n,r,o,i,a={label:0,sent:function(){if(1&o[0])throw o[1];return o[1]},trys:[],ops:[]};return i={next:c(0),throw:c(1),return:c(2)},"function"==typeof Symbol&&(i[Symbol.iterator]=function(){return this}),i;function c(c){return function(u){return function(c){if(n)throw new TypeError("Generator is already executing.");for(;i&&(i=0,c[0]&&(a=0)),a;)try{if(n=1,r&&(o=2&c[0]?r.return:c[0]?r.throw||((o=r.return)&&o.call(r),0):r.next)&&!(o=o.call(r,c[1])).done)return o;switch(r=0,o&&(c=[2&c[0],o.value]),c[0]){case 0:case 1:o=c;break;case 4:return a.label++,{value:c[1],done:!1};case 5:a.label++,r=c[1],c=[0];continue;case 7:c=a.ops.pop(),a.trys.pop();continue;default:if(!(o=a.trys,(o=o.length>0&&o[o.length-1])||6!==c[0]&&2!==c[0])){a=0;continue}if(3===c[0]&&(!o||c[1]>o[0]&&c[1]<o[3])){a.label=c[1];break}if(6===c[0]&&a.label<o[1]){a.label=o[1],o=c;break}if(o&&a.label<o[2]){a.label=o[2],a.ops.push(c);break}o[2]&&a.ops.pop(),a.trys.pop();continue}c=t.call(e,a)}catch(e){c=[6,e],r=0}finally{n=o=0}if(5&c[0])throw c[1];return{value:c[0]?c[1]:void 0,done:!0}}([c,u])}}};function o(){return n(this,void 0,Promise,function(){return r(this,function(e){switch(e.label){case 0:return[4,new Promise(function(e,t){var o="Unknown",i=!1;function a(t){i||(i=!0,e({isPrivate:t,browserName:o}))}function c(){var e=0,t=parseInt("-1");try{t.toFixed(t)}catch(t){e=t.message.length}return e}function u(){return n(this,void 0,void 0,function(){var e,t;return r(this,function(n){switch(n.label){case 0:return n.trys.push([0,2,,3]),[4,navigator.storage.getDirectory()];case 1:return n.sent(),a(!1),[3,3];case 2:return e=n.sent(),t=e instanceof Error&&"string"==typeof e.message?e.message:String(e),a(t.includes("unknown transient reason")),[3,3];case 3:return[2]}})})}function s(){var e;return n(this,void 0,Promise,function(){return r(this,function(t){switch(t.label){case 0:return"function"!=typeof(null===(e=navigator.storage)||void 0===e?void 0:e.getDirectory)?[3,2]:[4,u()];case 1:return t.sent(),[3,3];case 2:void 0!==navigator.maxTouchPoints?function(){var e=String(Math.random());try{var t=indexedDB.open(e,1);t.onupgradeneeded=function(t){var n=t.target.result,r=function(e){a(e)};try{n.createObjectStore("t",{autoIncrement:!0}).put(new Blob),r(!1)}catch(e){(e instanceof Error&&"string"==typeof e.message?e.message:String(e)).includes("are not yet supported")?r(!0):r(!1)}finally{n.close(),indexedDB.deleteDatabase(e)}},t.onerror=function(){return a(!1)}}catch(e){a(!1)}}():function(){var e=window.openDatabase,t=window.localStorage;try{e(null,null,null,null)}catch(e){return void a(!0)}try{t.setItem("test","1"),t.removeItem("test")}catch(e){return void a(!0)}a(!1)}(),t.label=3;case 3:return[2]}})})}function l(){navigator.webkitTemporaryStorage.queryUsageAndQuota(function(e,t){var n=Math.round(t/1048576),r=2*Math.round(function(){var e,t,n,r=window;return null!==(n=null===(t=null===(e=null==r?void 0:r.performance)||void 0===e?void 0:e.memory)||void 0===t?void 0:t.jsHeapSizeLimit)&&void 0!==n?n:1073741824}()/1048576);a(n<r)},function(e){t(new Error("detectIncognito somehow failed to query storage quota: "+e.message))})}function f(){void 0!==self.Promise&&void 0!==self.Promise.allSettled?l():(0,window.webkitRequestFileSystem)(0,1,function(){a(!1)},function(){a(!0)})}function d(){var e;return n(this,void 0,Promise,function(){var t,n,o;return r(this,function(r){switch(r.label){case 0:if("function"!=typeof(null===(e=navigator.storage)||void 0===e?void 0:e.getDirectory))return[3,5];r.label=1;case 1:return r.trys.push([1,3,,4]),[4,navigator.storage.getDirectory()];case 2:return r.sent(),a(!1),[3,4];case 3:return t=r.sent(),n=t instanceof Error&&"string"==typeof t.message?t.message:String(t),a(n.includes("Security error")),[2];case 4:return[3,6];case 5:(o=indexedDB.open("inPrivate")).onerror=function(e){o.error&&"InvalidStateError"===o.error.name&&e.preventDefault(),a(!0)},o.onsuccess=function(){indexedDB.deleteDatabase("inPrivate"),a(!1)},r.label=6;case 6:return[2]}})})}(function(){return n(this,void 0,Promise,function(){return r(this,function(e){switch(e.label){case 0:return 44!==c()&&43!==c()?[3,2]:(o="Safari",[4,s()]);case 1:return e.sent(),[3,6];case 2:return 51!==c()?[3,3]:(n=navigator.userAgent,o=n.match(/Chrome/)?void 0!==navigator.brave?"Brave":n.match(/Edg/)?"Edge":n.match(/OPR/)?"Opera":"Chrome":"Chromium",f(),[3,6]);case 3:return 25!==c()?[3,5]:(o="Firefox",[4,d()]);case 4:return e.sent(),[3,6];case 5:void 0!==navigator.msSaveBlob?(o="Internet Explorer",a(void 0===window.indexedDB)):t(new Error("detectIncognito cannot determine the browser")),e.label=6;case 6:return[2]}var n})})})().catch(t)})];case 1:return[2,e.sent()]}})})}Object.defineProperty(t,"__esModule",{value:!0}),t.detectIncognito=void 0,t.detectIncognito=o,"undefined"!=typeof window&&(window.detectIncognito=o),t.default=o}}[598](0,e),e=e.default}()});`);
      }

      const result = await window.detectIncognito()
      return {
        isPrivate: result.isPrivate,
        browserName: result.browserName
      }
    } catch (err) {
      return {
        isPrivate: false,
        browserName: 'Unknown',
        error: err.message
      }
    }
  }

  // ============ BROWSER INFO ============
  getBrowserInfo() {
    const nAgt = navigator.userAgent
    let browser = navigator.appName
    let version = '' + parseFloat(navigator.appVersion)
    let verOffset

    if ((verOffset = nAgt.indexOf('Edg')) != -1) { browser = 'Microsoft Edge'; version = nAgt.substring(verOffset + 4) }
    else if ((verOffset = nAgt.indexOf('Chrome')) != -1) { browser = 'Chrome'; version = nAgt.substring(verOffset + 7) }
    else if ((verOffset = nAgt.indexOf('Safari')) != -1) {
      browser = 'Safari'; version = nAgt.substring(verOffset + 7)
      if ((verOffset = nAgt.indexOf('Version')) != -1) version = nAgt.substring(verOffset + 8)
    } else if ((verOffset = nAgt.indexOf('Firefox')) != -1) { browser = 'Firefox'; version = nAgt.substring(verOffset + 8) }

    let ix
    if ((ix = version.indexOf(';')) != -1) version = version.substring(0, ix)
    if ((ix = version.indexOf(' ')) != -1) version = version.substring(0, ix)

    let os = 'Unknown'
    const clientStrings = [
      { s: 'Windows 10', r: /(Windows 10.0|Windows NT 10.0)/ },
      { s: 'Windows 11', r: /(Windows 11|Windows NT 11)/ },
      { s: 'Mac OS', r: /Mac OS X/ },
      { s: 'Linux', r: /(Linux|X11)/ },
      { s: 'Android', r: /Android/ },
      { s: 'iOS', r: /(iPhone|iPad|iPod)/ }
    ]
    for (const cs of clientStrings) { if (cs.r.test(nAgt)) { os = cs.s; break } }

    return {
      browser, version, os,
      mobile: /Mobile|mini|Fennec|Android|iP(ad|od|hone)/.test(navigator.appVersion)
    }
  }

  // ============ HARDWARE INFO ============
  getHardwareInfo() {
    try {
      const canvas = document.createElement('canvas')
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
      let gpu = 'Unknown'
      if (gl) {
        // Use unmasked renderer if available
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info')
        gpu = (debugInfo && gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)) || gl.getParameter(gl.RENDERER) || 'Unknown'
      }
      return { cpuCores: navigator.hardwareConcurrency, gpu }
    } catch (e) { return { error: e.message } }
  }

  // ============ HEAP / MEMORY INFO ============
  getHeapInfo() {
    if (window.performance && window.performance.memory) {
      const mem = window.performance.memory
      return {
        supported: true,
        jsHeapSizeLimit: mem.jsHeapSizeLimit,
        totalJSHeapSize: mem.totalJSHeapSize,
        usedJSHeapSize: mem.usedJSHeapSize,
        limitMB: Number((mem.jsHeapSizeLimit / 1048576).toFixed(2)),
        totalMB: Number((mem.totalJSHeapSize / 1048576).toFixed(2)),
        usedMB: Number((mem.usedJSHeapSize / 1048576).toFixed(2))
      }
    }
    return { supported: false }
  }

  // ============ NETWORK INFO (Network Information API) ============
  getNetworkInfo() {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection
    if (!conn) return { supported: false }
    return {
      effectiveType: conn.effectiveType || null,
      downlink: conn.downlink || null,
      rtt: conn.rtt || null,
      saveData: conn.saveData || false,
      type: conn.type || null
    }
  }

  // ============ SENSOR SUPPORT (Mobile) ============
  getSensorSupport() {
    return {
      deviceMotion: typeof DeviceMotionEvent !== 'undefined',
      deviceOrientation: typeof DeviceOrientationEvent !== 'undefined',
      ambientLight: typeof AmbientLightSensorEvent !== 'undefined' ||
                    (typeof window.AmbientLightSensor === 'function'),
      gyroscope: typeof Gyroscope !== 'undefined',
      accelerometer: typeof Accelerometer !== 'undefined',
      linearAcceleration: typeof LinearAccelerationSensor !== 'undefined',
      gravitySensor: typeof GravitySensor !== 'undefined',
      magnetometer: typeof Magnetometer !== 'undefined',
      absoluteOrientationSensor: typeof AbsoluteOrientationSensor !== 'undefined',
      relativeOrientationSensor: typeof RelativeOrientationSensor !== 'undefined'
    }
  }

  // ============ WebAssembly SUPPORT ============
  getWasmSupport() {
    const supported = typeof WebAssembly !== 'undefined'
    const simdSupported = (() => {
      try {
        // SIMD is available if the browser can compile a module using i32x4
        // This is a static check; full compile test moved to benchmark
        return typeof WebAssembly.SIMD !== 'undefined' || supported
      } catch (e) { return false }
    })()
    const sharedMemSupported = typeof SharedArrayBuffer !== 'undefined'
    return { supported, simd: simdSupported, sharedArrayBuffer: sharedMemSupported }
  }

  // ============ PERFORMANCE OBSERVER FEATURES ============
  getPerformanceFeatures() {
    if (typeof PerformanceObserver === 'undefined') return { supported: false }
    const supportedTypes = []
    const candidates = [
      'navigation', 'resource', 'mark', 'measure', 'paint',
      'longtask', 'element', 'first-input', 'layout-shift',
      'largest-contentful-paint', 'event', 'reload', 'back-forward-cache-restore'
    ]
    // PerformanceObserver.supportedEntryTypes is the reliable API
    if (PerformanceObserver.supportedEntryTypes) {
      return { supported: true, entryTypes: Array.from(PerformanceObserver.supportedEntryTypes).sort() }
    }
    // Fallback: probe each type individually
    for (const type of candidates) {
      try {
        const obs = new PerformanceObserver(() => {})
        obs.observe({ type, buffered: true })
        supportedTypes.push(type)
        obs.disconnect()
      } catch (e) { /* not supported */ }
    }
    return { supported: true, entryTypes: supportedTypes.sort() }
  }

  // ============ SCREEN EXTENDED (multi-monitor) ============
  getScreenExtended() {
    if (typeof screen === 'undefined') return { supported: false }
    return {
      isExtended: screen.isExtended !== undefined ? screen.isExtended : null,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      availExceedsScreen: screen.availWidth > screen.width
    }
  }

  // ============ HDR DETECTION ============
  detectHDR() {
    try {
      const canvas = document.createElement('canvas')
      canvas.width = 1
      canvas.height = 1

      const ctx = canvas.getContext('2d', { colorSpace: 'display-p3' })
      if (!ctx) return { supported: false, colorSpace: 'srgb' }

      return {
        supported: true,
        colorSpace: 'display-p3'
      }
    } catch (e) {
      return { supported: false, colorSpace: 'srgb' }
    }
  }

  // ============ AUDIO CONTEXT METADATA ============
  getAudioContextMetadata() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)()
      const result = {
        sampleRate: ctx.sampleRate,
        maxChannelCount: ctx.destination.maxChannelCount,
        channelCount: ctx.destination.channelCount,
        channelCountMode: ctx.destination.channelCountMode,
        channelInterpretation: ctx.destination.channelInterpretation,
        latency: ctx.latency !== undefined ? ctx.latency : null,
        baseLatency: ctx.baseLatency !== undefined ? ctx.baseLatency : null,
        outputLatency: ctx.outputLatency !== undefined ? ctx.outputLatency : null
      }
      ctx.close()
      return result
    } catch (e) {
      return { supported: false, error: e.message }
    }
  }

  // ============ BATTERY INFO (detailed) ============
  async getBatteryInfo() {
    try {
      if (!('getBattery' in navigator)) return { supported: false }
      const battery = await navigator.getBattery()
      return {
        supported: true,
        charging: battery.charging,
        level: battery.level,
        chargingTime: battery.chargingTime,
        dischargingTime: battery.dischargingTime,
        chargingTimeFinite: isFinite(battery.chargingTime),
        dischargingTimeFinite: isFinite(battery.dischargingTime)
      }
    } catch (e) {
      return { supported: false, error: e.message }
    }
  }

  // ============ CPU BENCHMARK (WebGL shader timing) ============
  async runCPUBenchmark() {
    // Worker-based parallel task timing
    return new Promise((resolve) => {
      const iterations = 5000000
      const code = `
        self.onmessage = function() {
          var start = performance.now();
          var x = 0;
          for (var i = 0; i < ${iterations}; i++) { x += Math.sin(i) * Math.cos(i); }
          self.postMessage({ elapsed: performance.now() - start, result: x });
        };
      `
      try {
        const blob = new Blob([code], { type: 'application/javascript' })
        const url = URL.createObjectURL(blob)
        const worker = new Worker(url)

        const timeout = setTimeout(() => {
          worker.terminate()
          URL.revokeObjectURL(url)
          resolve({ supported: true, timedOut: true })
        }, 5000)

        worker.onmessage = (e) => {
          clearTimeout(timeout)
          worker.terminate()
          URL.revokeObjectURL(url)
          resolve({
            supported: true,
            iterations,
            elapsedMs: Number(e.data.elapsed.toFixed(3)),
            opsPerMs: Number((iterations / e.data.elapsed).toFixed(2))
          })
        }
        worker.onerror = () => {
          clearTimeout(timeout)
          worker.terminate()
          URL.revokeObjectURL(url)
          resolve({ supported: false, error: 'Worker error' })
        }
        worker.postMessage('start')
      } catch (e) {
        resolve({ supported: false, error: e.message })
      }
    })
  }

  // ============ LANGUAGE INFO ============
  getLanguageInfo() {
    return {
      browserLanguage: navigator.language,
      systemLanguage: navigator.systemLanguage || navigator.language,
      userLanguage: navigator.userLanguage || navigator.language,
      languages: navigator.languages || [navigator.language]
    }
  }

  // ============ TIMEZONE INFO ============
  getTimezoneInfo() {
    const offset = new Date().getTimezoneOffset()
    return {
      offset,
      gmtHours: (offset / 60) * -1,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    }
  }

  // ============ VM DETECTION (SIMPLIFIED OUTPUT) ============
  async detectVM() {
    const scores = {}
    let totalScore = 0
    const results = []

    const addScore = (id, score, reason) => {
      scores[id] = { score, reason }
      totalScore += score
      results.push({ id, score, reason })
    }

    try {
      const canvas = document.createElement('canvas')
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')

      if (!gl) {
        addScore('webgl_unavailable', 15, 'WebGL not available')
      } else {
          let vendor = gl.getParameter(gl.VENDOR) || ''
          let renderer = gl.getParameter(gl.RENDERER) || ''
          if (!vendor || !renderer) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info')
            if (debugInfo) {
              if (!vendor) vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || ''
              if (!renderer) renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || ''
            }
          }
          if (vendor || renderer) {
            const vmIndicators = ['vmware', 'virtualbox', 'virtual', 'qemu', 'bochs', 'parallels', 'hyper-v', 'kvm', 'xen']
            const vendorLower = vendor.toLowerCase()
            const rendererLower = renderer.toLowerCase()

            for (const indicator of vmIndicators) {
              if (vendorLower.includes(indicator) || rendererLower.includes(indicator)) {
                addScore('webgl_vm_match', 40, `VM detected in WebGL: ${indicator}`)
                break
              }
            }
            if (!scores['webgl_vm_match']) {
              const softwareRenderers = ['swiftshader', 'llvmpipe', 'software', 'mesa', 'gallium', 'chromium']
              for (const sw of softwareRenderers) {
                if (rendererLower.includes(sw)) { addScore('webgl_software', 25, `Software renderer: ${sw}`); break }
              }
            }
            if (!scores['webgl_vm_match'] && !scores['webgl_software']) addScore('webgl_ok', 0, 'WebGL appears normal')
          } else { addScore('webgl_no_info', 10, 'WebGL vendor/renderer unavailable') }
      }
    } catch (e) { addScore('webgl_error', 10, `WebGL check error: ${e.message}`) }

    // --- WebGL2 VM check ---
    try {
      const canvas2 = document.createElement('canvas')
      const gl2 = canvas2.getContext('webgl2')
      if (!gl2) {
        addScore('webgl2_unavailable', 10, 'WebGL2 not available')
      } else {
        let vendor2 = gl2.getParameter(gl2.VENDOR) || ''
        let renderer2 = gl2.getParameter(gl2.RENDERER) || ''
        if (!vendor2 || !renderer2) {
          const dbg2 = gl2.getExtension('WEBGL_debug_renderer_info')
          if (dbg2) {
            if (!vendor2) vendor2 = gl2.getParameter(dbg2.UNMASKED_VENDOR_WEBGL) || ''
            if (!renderer2) renderer2 = gl2.getParameter(dbg2.UNMASKED_RENDERER_WEBGL) || ''
          }
        }
        const vmIndicators2 = ['vmware', 'virtualbox', 'virtual', 'qemu', 'bochs', 'parallels', 'hyper-v', 'kvm', 'xen']
        const r2 = renderer2.toLowerCase(), v2 = vendor2.toLowerCase()
        for (const ind of vmIndicators2) {
          if (r2.includes(ind) || v2.includes(ind)) {
            addScore('webgl2_vm_match', 40, `VM detected in WebGL2: ${ind}`)
            break
          }
        }
        if (!scores['webgl2_vm_match']) {
          const swRenderers = ['swiftshader', 'llvmpipe', 'software', 'mesa', 'gallium']
          for (const sw of swRenderers) {
            if (r2.includes(sw)) { addScore('webgl2_software', 20, `WebGL2 software renderer: ${sw}`); break }
          }
        }
      }
    } catch (e) { addScore('webgl2_error', 5, `WebGL2 check error: ${e.message}`) }

    // --- Heap size VM signal ---
    if (window.performance && window.performance.memory) {
      const limitMB = window.performance.memory.jsHeapSizeLimit / 1048576
      if (limitMB < 500) addScore('heap_low', 15, `Low JS heap limit: ${limitMB.toFixed(0)}MB`)
      else if (limitMB < 1000) addScore('heap_medium', 5, `Medium JS heap limit: ${limitMB.toFixed(0)}MB`)
      else addScore('heap_ok', 0, `JS heap limit normal: ${limitMB.toFixed(0)}MB`)
    }

    const width = screen.width, height = screen.height
    const colorDepth = screen.colorDepth

    if (width < 800 || height < 600) addScore('screen_low_res', 20, `Low resolution: ${width}x${height}`)

    const vmResolutions = ['800x600', '1024x768', '1280x720', '1280x800', '1366x768']
    const currentRes = `${width}x${height}`
    if (vmResolutions.includes(currentRes)) addScore('screen_vm_res', 10, `Common VM resolution: ${currentRes}`)
    if (colorDepth < 24) addScore('screen_color_depth', 20, `Low color depth: ${colorDepth}bit`)

    const aspectRatio = width / height
    if (aspectRatio < 1.3 || aspectRatio > 1.8) addScore('screen_aspect', 5, `Unusual aspect ratio: ${aspectRatio.toFixed(2)}`)
    if (width >= 1920 && height >= 1080 && colorDepth === 24 && !scores['screen_vm_res']) addScore('screen_ok', 0, 'Screen properties appear normal')

    // --- screen.isExtended signal ---
    if (typeof screen.isExtended !== 'undefined') {
      if (!screen.isExtended && screen.width <= 1920) {
        addScore('screen_not_extended', 3, 'Single display (non-extended)')
      }
    }

    if ('deviceMemory' in navigator) {
      const ram = navigator.deviceMemory
      if (ram <= 2) addScore('memory_low', 25, `Low RAM: ${ram}GB`)
      else if (ram <= 4) addScore('memory_medium', 10, `Medium RAM: ${ram}GB`)
      else addScore('memory_ok', 0, `RAM appears normal: ${ram}GB`)
    } else { addScore('memory_unavailable', 5, 'Device memory API unavailable') }

    if ('hardwareConcurrency' in navigator) {
      const cores = navigator.hardwareConcurrency
      if (cores <= 2) addScore('cpu_low_cores', 20, `Low CPU cores: ${cores}`)
      else if (cores <= 4) addScore('cpu_medium_cores', 5, `Medium CPU cores: ${cores}`)
      else addScore('cpu_ok', 0, `CPU cores appear normal: ${cores}`)
    } else { addScore('cpu_unavailable', 5, 'Hardware concurrency unavailable') }

    await this.checkCPUTiming(addScore)

    // --- Network API VM signal ---
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection
    if (conn) {
      if (!conn.effectiveType && !conn.downlink) addScore('network_empty', 10, 'Network API present but returned no data')
    }

    try {
      if ('getBattery' in navigator) {
        const battery = await navigator.getBattery()
        if (battery.charging && battery.level === 1) addScore('battery_suspicious', 15, 'Battery always charging at 100%')
        else addScore('battery_ok', 0, 'Battery API appears normal')
      } else { addScore('battery_unavailable', 10, 'Battery API unavailable') }
    } catch (e) { addScore('battery_unavailable', 10, 'Battery API unavailable') }

    const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0
    if (!hasTouch && screen.width < 1920) addScore('touch_missing', 10, 'No touch support on small screen')

    const plugins = navigator.plugins
    if (plugins.length === 0) addScore('plugins_none', 15, 'No browser plugins detected')
    else if (plugins.length < 3) addScore('plugins_few', 5, `Few plugins: ${plugins.length}`)

    const ua = navigator.userAgent.toLowerCase()
    const vmIndicators = ['headless', 'phantomjs', 'selenium', 'bot']
    for (const indicator of vmIndicators) {
      if (ua.includes(indicator)) { addScore('ua_vm_match', 30, `VM indicator in UA: ${indicator}`); break }
    }

    if (new Date().getTimezoneOffset() === 0) {
      const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone
      if (timezone === 'UTC' || !timezone) addScore('timezone_utc', 10, 'Timezone set to UTC')
    }

    const languages = navigator.languages
    if (!languages || languages.length === 0) addScore('lang_none', 10, 'No languages detected')
    else if (languages.length === 1) addScore('lang_single', 5, 'Only one language')

    // --- Sensor absence signal (mobile VMs rarely emulate sensors) ---
    const isMobileUA = /Mobile|Android|iPhone|iPad/.test(navigator.userAgent)
    if (isMobileUA) {
      const hasSensors = typeof DeviceMotionEvent !== 'undefined' && typeof DeviceOrientationEvent !== 'undefined'
      if (!hasSensors) addScore('mobile_no_sensors', 20, 'Mobile UA but no motion/orientation sensors')
    }

    // --- SharedArrayBuffer signal ---
    if (typeof SharedArrayBuffer === 'undefined') {
      addScore('sab_missing', 5, 'SharedArrayBuffer not available')
    }

    try {
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      ctx.textBaseline = 'top'
      ctx.font = '14px Arial'
      ctx.fillText('VM Detection', 2, 2)
      if (canvas.toDataURL().length < 500) addScore('canvas_small', 5, 'Unusual canvas output size')
    } catch (e) { addScore('canvas_error', 10, 'Canvas check failed') }

    const threshold = 50
    const isVM = totalScore >= threshold

    // SIMPLIFIED OUTPUT: just isVM boolean and details array
    return {
      isVM: isVM,
      details: results.filter(r => r.score > 0)
    }
  }

  async checkCPUTiming(addScore) {
    return new Promise((resolve) => {
      const start = performance.now()
      const workers = []
      let completed = 0
      const maxWorkers = 16

      for (let i = 0; i < maxWorkers; i++) {
        try {
          const blob = new Blob(['self.postMessage(1);'], { type: 'application/javascript' })
          const url = URL.createObjectURL(blob)
          const worker = new Worker(url)

          worker.onmessage = () => {
            completed++
            worker.terminate()
            URL.revokeObjectURL(url)
            if (completed === maxWorkers) {
              const elapsed = performance.now() - start
              if (elapsed > 100) addScore('cpu_timing_slow', 15, `Slow worker execution: ${elapsed.toFixed(2)}ms`)
              resolve()
            }
          }
          worker.onerror = () => {
            completed++
            worker.terminate()
            URL.revokeObjectURL(url)
            if (completed === maxWorkers) resolve()
          }
          workers.push(worker)
        } catch (err) {
          completed++
          if (completed === maxWorkers) resolve()
        }
      }
      setTimeout(() => { workers.forEach(w => { try { w.terminate() } catch (e) {} }); resolve() }, 5000)
    })
  }

  // ============ PERMISSIONS ============
  async getPermissions() {
    const permissionNames = ['geolocation', 'notifications', 'camera', 'microphone']
    const permissions = {}
    for (const name of permissionNames) {
      try {
        const status = await Promise.race([
          navigator.permissions.query({ name }),
          new Promise((resolve) => setTimeout(() => resolve({ state: 'timeout' }), 1000))
        ])
        permissions[name] = status.state
      } catch (e) { permissions[name] = 'not-supported' }
    }
    return permissions
  }

  // ============ CANVAS ============
  getCanvasFingerprint() {
    const canvas = document.createElement('canvas')
    canvas.width = 500
    canvas.height = 200
    const ctx = canvas.getContext('2d')

    const txt = "❁ I Want me a Tasty Fruit Salad!\n\r <🍏🍎🍐🍊🍋🍌🍉🍇🍓🍈🍒🍑🍍🥝>"
    ctx.textBaseline = 'top'
    ctx.font = "14px 'Arial'"
    ctx.textBaseline = 'alphabetic'
    ctx.fillStyle = '#f60'
    ctx.fillRect(125, 1, 62, 20)
    ctx.fillStyle = '#069'
    ctx.fillText(txt, 2, 15)
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)'
    ctx.fillText(txt, 4, 17)

    ctx.globalCompositeOperation = 'multiply'
    ctx.fillStyle = 'rgb(255,0,255)'
    ctx.beginPath(); ctx.arc(50, 50, 50, 0, Math.PI * 2, true); ctx.fill()
    ctx.fillStyle = 'rgb(0,255,255)'
    ctx.beginPath(); ctx.arc(100, 50, 50, 0, Math.PI * 2, true); ctx.fill()
    ctx.fillStyle = 'rgb(255,255,0)'
    ctx.beginPath(); ctx.arc(75, 100, 50, 0, Math.PI * 2, true); ctx.fill()

    ctx.fillStyle = 'rgb(255,0,255)'
    ctx.arc(75, 75, 75, 0, Math.PI * 2, true)
    ctx.arc(75, 75, 25, 0, Math.PI * 2, true)
    ctx.fill('evenodd')

    return canvas.toDataURL()
  }

  getCanvasEmojiRendering() {
    const canvas = document.createElement('canvas')
    canvas.width = 200
    canvas.height = 60
    const ctx = canvas.getContext('2d')
    ctx.font = '48px serif'
    ;['😀', '🎨', '🔥', '💻', '🌍'].forEach((e, i) => ctx.fillText(e, i * 40, 50))
    return canvas.toDataURL()
  }

  // ============ WEBGL (v1) ============
  getWebGlBasics() {
    const gl = this.getWebGLContext()
    if (!gl) return undefined
    // Use unmasked vendor/renderer if available
    const dbg = gl.getExtension('WEBGL_debug_renderer_info')
    const vendorUnmasked = (dbg && gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)) || gl.getParameter(gl.VENDOR) || ''
    const rendererUnmasked = (dbg && gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)) || gl.getParameter(gl.RENDERER) || ''
    return {
      version: gl.getParameter(gl.VERSION),
      vendor: gl.getParameter(gl.VENDOR),
      vendorUnmasked,
      renderer: gl.getParameter(gl.RENDERER),
      rendererUnmasked,
      shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
    }
  }

  getWebGlExtensions() {
    const gl = this.getWebGLContext()
    if (!gl) return undefined
    const attrs = gl.getContextAttributes() || {}
    return {
      contextAttributes: Object.keys(attrs).sort().map(k => `${k}=${attrs[k]}`),
      parameters: this.getWebGlParameters(gl),
      extensions: (gl.getSupportedExtensions() || []).sort(),
      shaderPrecisionFormats: this.getShaderPrecisionFormats(gl)
    }
  }

  getShaderPrecisionFormats(gl) {
    const shaders = ['VERTEX_SHADER', 'FRAGMENT_SHADER']
    const precisions = ['LOW_FLOAT', 'MEDIUM_FLOAT', 'HIGH_FLOAT', 'LOW_INT', 'MEDIUM_INT', 'HIGH_INT']
    const results = []
    for (const shader of shaders) {
      for (const precision of precisions) {
        try {
          const format = gl.getShaderPrecisionFormat(gl[shader], gl[precision])
          if (format) results.push(`${shader}.${precision}=${format.rangeMin},${format.rangeMax},${format.precision}`)
        } catch (e) {
          // Skip formats that cause errors
        }
      }
    }
    return results
  }

  getWebGLContext() {
    const canvas = document.createElement('canvas')
    return canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
  }

  getWebGlParameters(gl) {
    const params = [
      'MAX_TEXTURE_SIZE', 'MAX_VERTEX_ATTRIBS', 'MAX_VERTEX_UNIFORM_VECTORS',
      'MAX_VARYING_VECTORS', 'MAX_COMBINED_TEXTURE_IMAGE_UNITS', 'MAX_VERTEX_TEXTURE_IMAGE_UNITS',
      'MAX_TEXTURE_IMAGE_UNITS', 'MAX_FRAGMENT_UNIFORM_VECTORS', 'MAX_CUBE_MAP_TEXTURE_SIZE',
      'MAX_RENDERBUFFER_SIZE', 'MAX_VIEWPORT_DIMS', 'ALIASED_LINE_WIDTH_RANGE', 'ALIASED_POINT_SIZE_RANGE'
    ]
    const results = []
    for (const name of params) {
      try {
        // Check if the parameter actually exists before querying
        if (gl[name] !== undefined) {
          const val = gl.getParameter(gl[name])
          results.push(`${name}=${Array.isArray(val) ? val.join(',') : val}`)
        }
      } catch (e) {
        // Skip parameters that cause errors
      }
    }
    return results.sort()
  }

  // ============ WEBGL2 ============
  getWebGl2Basics() {
    const gl2 = this.getWebGL2Context()
    if (!gl2) return { supported: false }
    // Use unmasked vendor/renderer if available
    const dbg = gl2.getExtension('WEBGL_debug_renderer_info')
    const vendorUnmasked = (dbg && gl2.getParameter(dbg.UNMASKED_VENDOR_WEBGL)) || gl2.getParameter(gl2.VENDOR) || ''
    const rendererUnmasked = (dbg && gl2.getParameter(dbg.UNMASKED_RENDERER_WEBGL)) || gl2.getParameter(gl2.RENDERER) || ''
    return {
      supported: true,
      version: gl2.getParameter(gl2.VERSION),
      vendor: gl2.getParameter(gl2.VENDOR),
      vendorUnmasked,
      renderer: gl2.getParameter(gl2.RENDERER),
      rendererUnmasked,
      shadingLanguageVersion: gl2.getParameter(gl2.SHADING_LANGUAGE_VERSION)
    }
  }

  getWebGl2Extensions() {
    const gl2 = this.getWebGL2Context()
    if (!gl2) return { supported: false }
    const attrs = gl2.getContextAttributes() || {}
    return {
      supported: true,
      contextAttributes: Object.keys(attrs).sort().map(k => `${k}=${attrs[k]}`),
      parameters: this.getWebGl2Parameters(gl2),
      extensions: (gl2.getSupportedExtensions() || []).sort(),
      shaderPrecisionFormats: this.getShaderPrecisionFormats(gl2)
    }
  }

  getWebGL2Context() {
    const canvas = document.createElement('canvas')
    return canvas.getContext('webgl2')
  }

  getWebGl2Parameters(gl2) {
    const params = [
      'MAX_3D_TEXTURE_SIZE',
      'MAX_SAMPLES',
      'MAX_DRAW_BUFFERS',
      'MAX_COLOR_ATTACHMENTS',
      'MAX_UNIFORM_BLOCK_SIZE',
      'MAX_UNIFORM_BLOCKS_PER_SHADER',
      'MAX_COMBINED_UNIFORM_BLOCKS',
      'MAX_VARYING_COMPONENTS',
      'MAX_VERTEX_UNIFORM_COMPONENTS',
      'MAX_FRAGMENT_UNIFORM_COMPONENTS',
      'MAX_TEXTURE_IMAGE_UNITS',
      'MAX_COMBINED_TEXTURE_IMAGE_UNITS',
      'MAX_TRANSFORM_FEEDBACK_BUFFERS',
      'MAX_TRANSFORM_FEEDBACK_SEPARATE_COMPONENTS',
      'MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS',
      'MAX_VERTEX_OUTPUT_COMPONENTS',
      'MAX_ELEMENT_INDEX',
      'MAX_ELEMENTS_INDICES',
      'MAX_ELEMENTS_VERTICES',
      'MIN_PROGRAM_TEXEL_OFFSET',
      'MAX_PROGRAM_TEXEL_OFFSET'
    ]
    const results = []
    for (const name of params) {
      try {
        // Check if the parameter actually exists before querying
        if (gl2[name] !== undefined) {
          const val = gl2.getParameter(gl2[name])
          if (val !== null && val !== undefined) {
            results.push(`${name}=${Array.isArray(val) || val instanceof Int32Array ? Array.from(val).join(',') : val}`)
          }
        }
      } catch (e) {
        // Skip parameters that cause errors
      }
    }
    return results.sort()
  }

  // ============ AUDIO ============
  async getAudioFingerprint() {
    const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext
    if (!OfflineCtx) return undefined
    const ctx = new OfflineCtx(1, 44100, 44100)
    const osc = ctx.createOscillator()
    osc.type = 'triangle'
    osc.frequency.value = 10000
    const compressor = ctx.createDynamicsCompressor()
    compressor.threshold.value = -50
    compressor.knee.value = 40
    compressor.ratio.value = 12
    compressor.attack.value = 0
    compressor.release.value = 0.25
    osc.connect(compressor)
    compressor.connect(ctx.destination)
    osc.start(0)
    const buf = await ctx.startRendering()
    const data = buf.getChannelData(0)
    let sum = 0
    for (let i = 4500; i < Math.min(5000, data.length); i++) sum += Math.abs(data[i])
    return Number(sum.toFixed(12))
  }

  // ============ OTHER STABLE SIGNALS ============
  getScreenFrame() {
    if (!screen) return undefined
    const n = x => (typeof x === 'number' && isFinite(x) ? x : 0)
    return [n(screen.availLeft), n(screen.availTop),
            n(screen.width) - n(screen.availWidth) - n(screen.availLeft),
            n(screen.height) - n(screen.availHeight) - n(screen.availTop)]
  }

  async getFonts() {
    if (!document?.body) return undefined
    const fonts = [
      'Arial', 'Calibri', 'Cambria', 'Comic Sans MS', 'Consolas', 'Courier New',
      'Georgia', 'Helvetica', 'Impact', 'Lucida Console', 'Palatino', 'Tahoma',
      'Times New Roman', 'Trebuchet MS', 'Verdana', 'MS Gothic', 'MS UI Gothic', 'Segoe UI'
    ]
    const baseFonts = ['monospace', 'sans-serif', 'serif']
    const span = document.createElement('span')
    span.textContent = 'mmmmmmmmmmlli'
    span.style.cssText = 'position:absolute;left:-9999px;font-size:72px'
    document.body.appendChild(span)
    const baseline = {}
    baseFonts.forEach(base => { span.style.fontFamily = base; baseline[base] = { w: span.offsetWidth, h: span.offsetHeight } })
    const detected = []
    fonts.forEach(font => {
      for (const base of baseFonts) {
        span.style.fontFamily = `"${font}",${base}`
        if (span.offsetWidth !== baseline[base].w || span.offsetHeight !== baseline[base].h) { detected.push(font); break }
      }
    })
    span.remove()
    return detected.sort()
  }

  getFontPreferences() {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    if (!ctx) return undefined
    const text = 'mmMwWLliI0O&1'
    const fonts = { default: 'sans-serif', serif: 'serif', sans: 'sans-serif', mono: 'monospace' }
    const measurements = {}
    Object.entries(fonts).forEach(([name, font]) => {
      ctx.font = `48px ${font}`
      measurements[name] = Number(ctx.measureText(text).width.toFixed(12))
    })
    return measurements
  }

  getMathFingerprint() {
    return {
      acos: Math.acos(0.123), asin: Math.asin(0.123), atan: Math.atan(0.5),
      sin: Math.sin(1), cos: Math.cos(2.566), tan: Math.tan(-0.96),
      exp: Math.exp(1), log1p: Math.log1p(10), powPI: Math.pow(Math.PI, -100)
    }
  }

  getPlugins() {
    if (!navigator.plugins) return []
    const res = []
    for (let i = 0; i < navigator.plugins.length; i++) {
      const p = navigator.plugins[i]
      res.push({ name: p.name, description: p.description })
    }
    return res
  }

  getTouchSupport() {
    return {
      maxTouchPoints: navigator.maxTouchPoints || 0,
      touchEvent: 'ontouchend' in window,
      touchStart: 'ontouchstart' in window
    }
  }

  // ============ OUTPUT ============
  async generate() {
    const result = await this.collectAll()

    const output = {
      components: result.components,
      additionalData: result.additionalData,
      timestamp: result.timestamp
    }

    window.fingerprintResult = output
    debugLog(JSON.stringify(output, null, 2))
    return output
  }
}

// ============ JWE ENCRYPTION CLASS ============
class JWEEncryption {
  constructor(rsaPublicKeyPem) {
    this.rsaPublicKeyPem = rsaPublicKeyPem;
  }

  async importPublicKey() {
    const pemContents = this.rsaPublicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '');
    
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    return await crypto.subtle.importKey(
      'spki',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-1'  // ← IMPORTANT: SHA-1 for PHP compatibility
      },
      false,
      ['encrypt']
    );
  }

  async generateAESKey() {
    return await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt']
    );
  }

  async encryptAES(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      aesKey,
      data
    );
    
    const encryptedArray = new Uint8Array(encrypted);
    const ciphertext = encryptedArray.slice(0, -16);
    const tag = encryptedArray.slice(-16);
    
    return { iv, ciphertext, tag };
  }

  async encryptRSA(publicKey, aesKeyBytes) {
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP'
      },
      publicKey,
      aesKeyBytes
    );
    
    return new Uint8Array(encrypted);
  }

  base64UrlEncode(bytes) {
    // Base64URL encoding for PHP compatibility
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  async encrypt(plaintext) {
    debugLog('Starting JWE encryption...');
    
    const publicKey = await this.importPublicKey();
    debugLog('✓ RSA public key imported');
    
    const aesKey = await this.generateAESKey();
    debugLog('✓ AES-256 key generated');
    
    const aesKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', aesKey));
    debugLog('✓ AES key exported as bytes');
    
    const { iv, ciphertext, tag } = await this.encryptAES(aesKey, plaintext);
    debugLog('✓ Plaintext encrypted with AES-GCM');
    
    const encryptedKey = await this.encryptRSA(publicKey, aesKeyBytes);
    debugLog('✓ AES key encrypted with RSA-OAEP');
    
    const ctWithTag = new Uint8Array(ciphertext.length + tag.length);
    ctWithTag.set(ciphertext, 0);
    ctWithTag.set(tag, ciphertext.length);
    
    const jwePayload = {
      ek: this.base64UrlEncode(encryptedKey),
      iv: this.base64UrlEncode(iv),
      ct: this.base64UrlEncode(ctWithTag)
    };
    
    debugLog('✓ JWE encryption complete');
    
    return jwePayload;
  }
}

// [Copy everything from your script up to the void (async () => { line, then replace with this verbose version]

void (async () => {
  debugLog('========================================');
  debugLog('🚀 Fingerprint Script Started');
  debugLog('========================================');
  
  // Check 1: Endpoint URL
  if (!window.FP_ENDPOINT_URL) {
    debugError('❌ BLOCKED: window.FP_ENDPOINT_URL is not defined');
    debugLog('Script will not run - endpoint URL missing');
    return;
  }
  debugLog('✓ Endpoint URL found:', window.FP_ENDPOINT_URL);

  // Signal that fingerprint script has loaded and started
  window.FINGERPRINT_STARTED = true;
  debugLog('✓ Set window.FINGERPRINT_STARTED = true');

  // Check 2: Valid session
  debugLog('Checking session status...');
  debugLog('  window.HAS_VALID_SESSION =', window.HAS_VALID_SESSION);
  if (window.HAS_VALID_SESSION === true) {
    debugLog('✓ User has valid session - skipping fingerprint collection');
    debugLog('🎉 ALLOWING PAGE ACCESS (valid session)');
    return;
  }
  debugLog('  No valid session - will collect fingerprint');

  // Check 3: Already sent recently
  const sentAt = sessionStorage.getItem("fp_sent");
  const TTL_MS = 10000; // 10 seconds
  debugLog('Checking if fingerprint submission recently started...');
  debugLog('  sessionStorage.fp_sent =', sentAt);
  if (sentAt && (Date.now() - Number(sentAt) < TTL_MS)) {
    debugLog('⚠️  BLOCKED: fingerprint submission recently started');
    return;
  }

  sessionStorage.setItem("fp_sent", Date.now().toString());
  debugLog('✓ Set sessionStorage.fp_sent =', sessionStorage.getItem("fp_sent"));

  // Generate UUID
  const uuid = (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
  debugLog('✓ Generated UUID:', uuid);

  // Collect fingerprint
  debugLog('');
  debugLog('📊 Starting fingerprint collection...');
  const system = new CompleteFingerprintSystem();
  const payload = await system.generate();
  debugLog('✓ Fingerprint collected:', Object.keys(payload.components).length, 'components');

  // NEW - ENCRYPTED (KEEP EVERYTHING ELSE THE SAME)
  try {
    const plaintext = `${uuid} ${JSON.stringify(payload)}`;
    debugLog('');
    debugLog('📦 Preparing data...');
    debugLog('  Plaintext length:', plaintext.length, 'bytes');
    
    let requestBody;
    let contentType;
    
    // Check for RSA key
    debugLog('Checking for RSA public key...');
    debugLog('  window.FP_RSA_PUBLIC_KEY_PEM present:', !!window.FP_RSA_PUBLIC_KEY_PEM);
    
    if (window.FP_RSA_PUBLIC_KEY_PEM) {
      debugLog('');
      debugLog('🔐 Encrypting fingerprint data...');
      const jwe = new JWEEncryption(window.FP_RSA_PUBLIC_KEY_PEM);
      const encrypted = await jwe.encrypt(plaintext);
      
      requestBody = JSON.stringify(encrypted);
      contentType = 'application/json';
      debugLog('✓ Fingerprint encrypted with JWE');
      debugLog('  Encrypted payload size:', requestBody.length, 'bytes');
      debugLog('  ek length:', encrypted.ek.length);
      debugLog('  iv length:', encrypted.iv.length);
      debugLog('  ct length:', encrypted.ct.length);
    } else {
      debugWarn('⚠️  No RSA key - sending plaintext');
      requestBody = plaintext;
      contentType = 'text/plain';
    }
    
    debugLog('');
    debugLog('📡 Sending fingerprint to server...');
    debugLog('  URL:', window.FP_ENDPOINT_URL);
    debugLog('  Method: POST');
    debugLog('  Content-Type:', contentType);
    debugLog('  Body size:', requestBody.length, 'bytes');
    
    const fpRes = await fetch(window.FP_ENDPOINT_URL, {
      method: "POST",
      headers: {
        "Content-Type": contentType
      },
      body: requestBody,
      keepalive: true
    });

    debugLog('');
    debugLog('📬 Server response received:');
    debugLog('  Status:', fpRes.status, fpRes.statusText);
    debugLog('  OK:', fpRes.ok);

    // Check if request succeeded
    if (fpRes.ok || fpRes.status === 204) {
      debugLog('');
      debugLog('✅ ✅ ✅ Fingerprint sent successfully! ✅ ✅ ✅');
      debugLog('');
      debugLog('🎉 Dispatching fingerprintSuccess event...');
      window.dispatchEvent(new CustomEvent('fingerprintSuccess'));
      debugLog('✓ Event dispatched');
      sessionStorage.removeItem("fp_sent");
      
      debugLog('');
      debugLog('🔄 Reloading page to get session token...');
      debugLog('  After reload, user should have access');
      window.location.reload();
    } else {
      debugLog('');
      debugError('❌ ❌ ❌ Server returned error status ❌ ❌ ❌');
      debugError('  Status:', fpRes.status);
      debugError('  Status Text:', fpRes.statusText);
      
      // Try to read response body
      try {
        const responseText = await fpRes.text();
        debugError('  Response body:', responseText);
      } catch (e) {
        debugError('  Could not read response body');
      }
      
      debugLog('');
      debugLog('🎯 Dispatching fingerprintError event...');
      window.dispatchEvent(new CustomEvent('fingerprintError', { 
        detail: `HTTP ${fpRes.status}: ${fpRes.statusText}`
      }));
      sessionStorage.removeItem("fp_sent");
      debugLog('⚠️  PAGE MAY REMAIN BLOCKED DUE TO ERROR');
    }
  } catch (e) {
    debugLog('');
    debugError('❌ ❌ ❌ Exception occurred ❌ ❌ ❌');
    debugError('  Error type:', e.name);
    debugError('  Error message:', e.message);
    debugError('  Stack trace:', e.stack);
    
    debugLog('');
    debugLog('🎯 Dispatching fingerprintError event...');
    window.dispatchEvent(new CustomEvent('fingerprintError', { 
      detail: e.message || 'Network error'
    }));
    sessionStorage.removeItem("fp_sent");
    debugLog('⚠️  PAGE MAY REMAIN BLOCKED DUE TO ERROR');
    debugError('Fingerprint error:', e);
  }
  
  debugLog('');
  debugLog('========================================');
  debugLog('🏁 Fingerprint Script Execution Complete');
  debugLog('========================================');
})();
