## Licenses Reuse Analysis
This folder documents our license reuse analysis.

 - `lic_scanner.py` collects all license files from suspected apps(`.lic` files).
 - `lic_reuse_analysis.py` analyze license reuse.

The analysis is based on the assumption that differnet apps who bought the same SDK should get different licenses. If the license is the same, it might be illegal
reuse of license.

### Naming Rules
Some explanation on the naming of the analysis results: 
- `.txt` means the results of license scanner, it records all the extracted license file and it’s md5; 
- `.txt.reuse_analysis` is the results of license reuse analysis, it group all the apps and licenses under the same md5; 
- `.txt.reuse_analysis.suspected` is the results of suspected cases, it filter out licenses that are not reused or are reused by likely same app developers, 
   only list licenses that are reused by different apps.

The examples are as follows:
- all_apps_licenses.txt
- all_apps_licenses.txt.reuse_analysis
- all_apps_licenses.txt.reuse_analysis.suspected


### Example of License Reuse
One example: 68bfc3d4:
- `com.rrs.waterstationbuyer_78 liveness.lic`
-	`com.chinawidth.module.mashanghua_27 liveness.lic`

These two apps are very likely from different developers but are using the same license: 
- [com.chinawidth.module.mashanghua_27](https://android.kuchuan.com/page/detail/download?package=com.chinawidth.module.mashanghua&infomarketid=7&site=0#!/day/com.chinawidth.module.mashanghua) 
- [com.rrs.waterstationbuyer_78](https://www.qimai.cn/andapp/baseinfo/appid/566649) 

### Q&A
 1. How do we know these license files are ML license?
 >We are not 100 percent sure about it. I collected these licenses file from suspected ML apps.
 >Some of them you can tell by name, like `liveness.lic`. Btw, at least all SenseTime license are for ML.

 2. How do we know the apps are from different companies?
 >We are also not quite sure for now, that’s why I mark it suspected. 
 >I already excluded apps with similar names or under same company, only mark those apps who are very different and seems to be from different companies. 
 >I manually checked a few, and I found both possitive and negative cases. For example, it's possible that two apps look very different but from the same company.
 >It's also possible they are from different companines. like these two apps:
