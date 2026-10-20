/* ios.js - iOS enrichment. Prefer sysctlbyname over MobileGestalt (always
 * readable, no entitlement). ObjC.classes.UIDevice requires UIKit to be
 * loaded — guard with objcAvailable() && findModuleBase('UIKit'). On
 * early-attach before UIApplicationMain, UIKit is absent and UIDevice is
 * undefined; on Frida 17 agents the ObjC bridge itself is absent and the
 * sysctl values are all we report.
 */
function iosGetSystemInfo(result, warnings) {
    result.osDetail = '';
    try {
        var build = sysctlStr('kern.osversion');         /* e.g. 21E219 */
        var prod  = sysctlStr('kern.osproductversion');  /* e.g. 17.4 */
        var machine = sysctlStr('hw.machine');           /* e.g. iPhone16,2 */
        if (prod) {
            result.osDetail = 'iOS ' + prod + (build ? ' (' + build + ')' : '');
            if (machine) result.osDetail += ' (' + machine + ')';
        } else if (machine) {
            result.osDetail = 'iOS (' + machine + ')';
        }
        if (machine) result.hwModel = machine;
        result.kernel = sysctlStr('kern.osrelease');
    } catch(e) { warnings.push('ios_sysctl:' + e.message); }

    /* Hostname without ObjC: kern.hostname is readable from any process. */
    if (!result.hostname) {
        try { result.hostname = sysctlStr('kern.hostname'); } catch(e) {}
    }

    /* UIKit-guarded ObjC path — supplement when UIKit is loaded. */
    try {
        if (objcAvailable() && findModuleBase('UIKit') !== null) {
            var device = ObjC.classes.UIDevice.currentDevice();
            if (!result.osDetail) {
                result.osDetail = 'iOS ' + device.systemVersion().toString() + ' (' + device.model().toString() + ')';
            }
            result.hostname = device.name().toString();
        }
    } catch(e) { warnings.push('ios_uidevice:' + e.message); }
}
