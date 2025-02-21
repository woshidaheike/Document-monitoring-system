## 基于python代码实现的文件监控系统

### 功能

#### 该系统能对指定的文件夹进行监控,记录文件夹内文件的操作包含添加,删除,更改,重命名.并且基于virustotalapi对新添加的文件进行分析,判断是否为恶意文件,若是恶意文件会向用户邮箱发送邮件提示

### 使用方法

#### 1.下载模块

pip install -r requirements.txt

#### 2.修改代码

 （1）申请virustotal账号获得api

 （2）申请网易邮箱smtp授权码

 （3）修改代码

 API_KEY=“你的api”

 FROM=“发送信息的邮箱”

 TO=“接受信息的邮箱”

 SMTPUSER=“网易邮箱账号”

 SMTPPW=“你的smtp授权码”

106行 target_folder=“你要监控的目录”（注意双斜线防止转移）

#### 3.运行代码

pyhton surveillance.py

程序默认不会结束想要结束程序ctrl+c即可






