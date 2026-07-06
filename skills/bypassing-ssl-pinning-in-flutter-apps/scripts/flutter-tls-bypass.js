/*
 * flutter-tls-bypass.js
 *
 * Frida hook that defeats certificate validation inside a Flutter app's
 * statically-linked BoringSSL (libflutter.so / Flutter.framework).
 *
 * Because the engine is stripped, the cert-verification routine has no exported
 * symbol and is located by scanning the module's executable memory for a byte
 * PATTERN. Patterns are architecture- and engine-version specific: the examples
 * below are illustrative placeholders. Source current, tested patterns from
 * https://github.com/NVISOsecurity/disable-flutter-tls-verification and add the
 * one matching the target's ABI + engine version.
 *
 * Usage:
 *   frida -U -f com.target.app -l scripts/flutter-tls-bypass.js
 *   (iOS: -n "AppName" against a jailbroken device)
 */

'use strict';

// Module name differs per platform.
const FLUTTER_MODULE = Process.platform === 'darwin' ? 'Flutter' : 'libflutter.so';

// Map Process.arch -> a memory scan pattern for the verify routine's prologue.
// Replace these with current patterns for your target build.
const PATTERNS = {
  arm64: 'FF 03 03 D1 FD 7B 0? A9 F? ?? 00 F9',   // placeholder: update per engine version
  arm:   'F0 B5 03 AF 2D E9 00 0F',               // placeholder
  x64:   '55 41 57 41 56 41 55 41 54 53',         // placeholder
};

function hookVerify(mod) {
  const pattern = PATTERNS[Process.arch];
  if (!pattern) {
    console.log('[!] No pattern for arch ' + Process.arch + ' — add one.');
    return;
  }

  const matches = Memory.scanSync(mod.base, mod.size, pattern);
  if (matches.length === 0) {
    console.log('[!] Pattern not found in ' + mod.name +
                ' — likely a different engine version. Update the pattern.');
    return;
  }

  matches.forEach(function (m, i) {
    Interceptor.attach(m.address, {
      onLeave: function (retval) {
        // Force the verification result to "OK" (BoringSSL: ssl_verify_ok / 1).
        retval.replace(0x1);
      },
    });
    console.log('[+] Hooked verify candidate #' + i + ' @ ' + m.address);
  });
}

function main() {
  const mod = Process.findModuleByName(FLUTTER_MODULE);
  if (!mod) {
    // Engine may load slightly after start; retry briefly.
    const t = setInterval(function () {
      const m = Process.findModuleByName(FLUTTER_MODULE);
      if (m) { clearInterval(t); console.log('[+] ' + FLUTTER_MODULE + ' loaded'); hookVerify(m); }
    }, 200);
    return;
  }
  console.log('[+] ' + FLUTTER_MODULE + ' base ' + mod.base);
  hookVerify(mod);
}

setImmediate(main);
