# daibutsuCFW  

## how to make custom firmware  
```
./ipsw <input.ipsw> <target.ipsw> -daibutsu [-memory] [-bbupdate]
```

## how to restore with custom firmware  
For A5 devices, restore from `kDFU mode` or `pwned DFU mode` or `pwned Recovery Mode`.  
For A6 devices, restore from `pwned DFU` mode or `pwned Recovery Mode`.  

## references  
### list of original keys in xpwn/ipsw-patch  
| key | type | description | 
|---------|----------|----------|  
| hwmodel | String (ex. `N42`) | Used to move the jetsamproperties  daemon (com.apple.jetsamproperties.`XXX`.plist) for iOS 8 untether, such as daibutsu. |
| needPref | Bool | Set SBShowNonDefaultSystemApps on SpringBoard. This is required to display the Non-Default apps on the home screen on some devices. |
| PackagePath | String | This is the path to reference when incorporating package such as cydia into CFW. The format of the file must be tape archive. |
| UntetherPath | String | This is the path to reference when incorporating untether package such as daibutsu into CFW. The format of the file must be tape archive. |
| RamdiskPackage | String | This is the path to reference when incorporating package into RestoreRamdisk. The format of the file must be tape archive. |
| RamdiskReboot | String | This is the path to refer to the file to replace the /sbin/reboot file on RestoreRamdisk. Replace the /sbin/reboot executable in RestoreRamdisk and perform any action after the restore. | 

### list of flags and devices supported by haxx_overwrite (dyld haxx)
| flag | device | 
|---------|----------|
| `-n94` | iPhone 4S |
| `-n42` | iPhone 5 [iPhone5,2] |
| `-n78` | iPod touch 5th gen |
| `-k93a` | iPad 2 [iPad2,4] |
| `-p105` | iPad mini [iPad2,5] |
| `-p106` | iPad mini [iPad2,6] |
| `-p107` | iPad mini [iPad2,7] |
| `-j1` | iPad 3rd gen [iPad3,1] |
| `-j2` | iPad 3rd gen [iPad3,2] |
| `-j2a` | iPad 3rd gen [iPad3,3] |
