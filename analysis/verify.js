// Runtime verification for the ad-free patch on Bounce Defense 1.19.7.
//
// Confirms three things on a live device:
//   1. AdsSelfManager.ShowAds is still called by the game (reward buttons work).
//   2. The VIP gate returns true, so ShowAds completes instantly.
//   3. The SDK-level show paths are never reached (no ad is ever requested/shown).
//
// Usage:
//   frida -U -f com.minigamelab.bouncedefense -l analysis/verify.js --no-pause
//   (or: python -m frida_tools? no -- plain `frida` CLI is enough)

const MODULE = 'libil2cpp.so';

// RVAs come from analysis/il2cpp/dump.cs (Unity 6000.3.10f1, metadata v39).
const TARGETS = [
  ['AdsSelfManager::ShowAds', 0x176A5F8, 'game ad funnel'],
  ['AdsSelfManager::IsVipNoAdMonthlyProActive', 0x176A7C8, 'patched -> must return 1'],
  ['AdInterstitialConfig::CanShowAdInterstitial', 0x176B55C, 'patched -> must return 0'],
  ['StudioHelper::ShowAds', 0x1FD40A8, 'must NOT be reached'],
  ['VoodooSauce::ShowBanner', 0x3003300, 'must NOT be reached'],
  ['VoodooSauce::ShowInterstitial', 0x30033C8, 'must NOT be reached'],
  ['VoodooSauce::ShowRewardedVideo', 0x3003824, 'must NOT be reached'],
];

function fmt(x) {
  try { return x.toString(); } catch (e) { return '<' + x + '>'; }
}

function start() {
  const base = Module.findBaseAddress(MODULE);
  if (!base) {
    console.log('[!] ' + MODULE + ' not loaded yet, retrying...');
    return setTimeout(start, 500);
  }
  console.log('[*] ' + MODULE + ' base = ' + base);

  for (const [name, rva, note] of TARGETS) {
    if (typeof rva !== 'number' || rva <= 0) continue;
    const addr = base.add(rva);
    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          // ShowAds(AdType adType /*w1*/, Action<bool> cb /*x2*/, string placement /*x3*/)
          let extra = '';
          if (name === 'AdsSelfManager::ShowAds') {
            const adType = args[1].toInt32();
            const label = { 0: 'NONE', 1: 'REWARDED', 2: 'INTERSTITIAL', 3: 'BANNER' }[adType] || adType;
            extra = ' adType=' + label;
          }
          console.log('[CALL] ' + name + extra + '   << ' + note);
        },
        onLeave(retval) {
          if (name.includes('IsVip')) console.log('       -> returns ' + retval.toInt32() + ' (want 1)');
          if (name.includes('CanShowAdInterstitial')) console.log('       -> returns ' + retval.toInt32() + ' (want 0)');
        },
      });
    } catch (e) {
      console.log('[!] could not hook ' + name + ': ' + e);
    }
  }
  console.log('[*] hooks installed — play a level, use a reward button, rotate through the shop.');
}

setImmediate(start);
