# Required Reason API Inventory

Status: no required-reason API is used. The current Swift sources do not call the file timestamp, system boot time, disk space, active keyboards or user defaults categories.

Any new call must add its reason code to both `PrivacyInfo.xcprivacy` files in the same commit, and update this inventory.
