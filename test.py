import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import datetime
import virustotal_python
import hashlib
import smtplib
from email.utils import formataddr
from email.mime.text import MIMEText
newly_created_files = set()
API_KEY = "15b945c29bfc1f8578bbcd6f17e9e0be48eafdfcf0795ba98f8e823b8e074b8d" #apikey

FROM="15225096100@163.com"
TO='3241986481@qq.com'
SMTPUSER="15225096100"
SMTPPW="ABc4n3ANyQfYFsWB"
#日志函数
def  log(data):
    with open('log.txt', mode="a",encoding="utf-8") as f:
        f.write(data+"\n")
#邮箱函数
def mail(file_name,file_type,file_path):
    msg = MIMEText("文件名：{0} 文件类型：{1} 文件路径：{2}".format(file_name,file_type,file_path), 'html', 'utf-8')
    msg["From"] = formataddr(["黑客警告", FROM])
    msg['To'] =TO
    msg['Subject'] = '有恶意文件上传'
    server = smtplib.SMTP_SSL('smtp.163.com')
    server.login(SMTPUSER, SMTPPW)
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()
# 计算文件的哈希值（这里以 MD5 为例，也可以用 SHA-256 等）
def calculate_file_hash(file_path):
    hash_object = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_object.update(chunk)
    return hash_object.hexdigest()
# 上传文件进行分析
def upload_file_for_analysis(file_path):
    try:
        with virustotal_python.Virustotal(API_KEY) as vt:
            file_hash = calculate_file_hash(file_path)
            # 先检查文件哈希是否已在 VirusTotal 有分析记录
            try:
                url = f"/files/{file_hash}"
                response = vt.request(url)
                print("文件已在 VirusTotal 有分析记录，获取结果：")
                attributes = response.data.get("attributes", {})
                file_name = attributes.get("meaningful_name", "未知文件名")
                file_type = attributes.get("type_tag", "未知文件类型")
                if "last_analysis_stats" in attributes and attributes["last_analysis_stats"]["malicious"] >= 3:
                    mail(file_name, file_type, file_path)
                else:
                    print("{0}文件安全".format(file_path))
            except virustotal_python.VirustotalError as e:
                # 这里修改获取响应码的方式
                response_code = e.response.status_code if hasattr(e, "response") and hasattr(e.response, "status_code") else None
                if response_code == 404:  # 哈希不存在，上传文件
                    with open(file_path, "rb") as file:
                        files = {"file": (file_path, file)}
                        response = vt.request("/files", files=files, method="POST")
                        print("文件上传成功，分析结果：")
                        attributes = response.data.get("attributes", {})
                        file_name = attributes.get("meaningful_name", "未知文件名")
                        file_type = attributes.get("type_tag", "未知文件类型")
                        if "last_analysis_stats" in attributes and attributes["last_analysis_stats"]["malicious"] >= 3:
                            mail(file_name, file_type, file_path)
                        else:
                            print("{0}文件安全".format(file_path))
                else:
                    print(f"发生错误：{e}")
    except virustotal_python.VirustotalError as e:
        print(f"与 VirusTotal 交互时出错: {e}")
#文件监控类
class FileChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not event.is_directory:
            log(f"{time} 文件 {event.src_path} 已添加到文件夹中。")
            upload_file_for_analysis(event.src_path)
            newly_created_files.add(event.src_path)

    def on_deleted(self, event):
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not event.is_directory:
            log(f"{time} 文件 {event.src_path} 已从文件夹中删除。")

    def on_moved(self, event):
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not event.is_directory:
            src_dir = os.path.dirname(event.src_path)
            dest_dir = os.path.dirname(event.dest_path)
            if src_dir == dest_dir:
                log(f"{time} 文件 {event.src_path} 已被重命名为 {event.dest_path}。")
            else:
                log(f"{time} 文件 {event.src_path} 已移动到 {event.dest_path}。")
    def on_modified(self, event):
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not event.is_directory:
            if event.src_path in newly_created_files:
                newly_created_files.remove(event.src_path)
                return
            log(f"{time} 文件 {event.src_path} 的内容已被修改，发出警报！")
#main函数
if __name__ == "__main__":
    target_folder = 'D:\\phpstudy_pro\\WWW\\upload-labs\\upload'  # 这里设置为你要监控的文件夹路径，当前设置为当前目录，可按需修改
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=target_folder, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()