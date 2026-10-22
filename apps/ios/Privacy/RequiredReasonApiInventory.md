# Required Reason API Inventory

Status: one required-reason category, used only by the packet tunnel extension. The Swift sources do not call the file timestamp, system boot time, disk space, active keyboards or user defaults categories.

| Category | Reason | Target | Source |
| --- | --- | --- | --- |
| `NSPrivacyAccessedAPICategorySystemBootTime` | `35F9.1` (measure elapsed time between events inside the app) | `NetworkCorePacketTunnel` | The linked Rust runtime (`crates/engine-embedded`) reads the monotonic clock (`mach_absolute_time` / `clock_gettime`) for timers, timeouts and TCP retransmission. The value never leaves the device. |

`NetworkCoreApp` does not link the runtime, so its manifest declares no required-reason API.

Any new call must add its reason code to the `PrivacyInfo.xcprivacy` of every target that links it, in the same commit, and update this inventory.
