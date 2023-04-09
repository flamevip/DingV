import requests
import json
import time
import configparser
import logging
import atexit
import threading
from dingtalkchatbot.chatbot import DingtalkChatbot

def read_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return config

def get_file_report(api_key, file_id):
    url = f'https://www.virustotal.com/api/v3/files/{file_id}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    return response

def send_alert_to_dingtalk(webhook, message):
    xiaoding = DingtalkChatbot(webhook)
    xiaoding.send_text(msg=message)

def get_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return dict(config.items("SHA256_Mappings"))

def create_dingtalk_bot(webhook_url):
    return DingtalkChatbot(webhook_url)

def send_exit_message(dingtalk):
    message = "程序已经终止"
    dingtalk.send_text(msg=message, is_at_all=True)

def monitor_sha256(sha256_mapping, dingtalk, wbapi, threshold=51):
    while True:
        try:
            for file_id, name in sha256_mapping.items():
                url = f'https://api.threatbook.cn/v3/file/report/multiengines?apikey={wbapi}&sha256={file_id}'
                response = requests.get(url)
                data_size = len(response.content)
                if data_size > threshold:
                    logging.warning(f"警告：{url} 返回的数据大小为 {data_size} 字节！")
                    message = f"V步警告：{name}({file_id}) 返回的数据大小为 {data_size} 字节！已被上传"
                    dingtalk.send_text(msg=message, is_at_all=True)
            time.sleep(36)
        except Exception as e:
            logging.error(f"发生异常: {e}")
            message = f"程序发生异常: {e}"
            dingtalk.send_text(msg=message, is_at_all=True)
            time.sleep(60)

def monitor_virustotal(sha256_mapping, api_key, dingtalk_webhook):
    try:
        while True:
            for file_id, name in sha256_mapping.items():
                response = get_file_report(api_key, file_id)

                if response.status_code == 200:
                    report = response.json()
                    malicious = report['data']['attributes']['last_analysis_stats']['malicious']
                    if malicious == 0:
                        alert_message = f'VT警告：文件 {name}（SHA256: {file_id}）已被上传。'
                        send_alert_to_dingtalk(dingtalk_webhook, alert_message)
                        print(alert_message)

                time.sleep(15)
    finally:
        exit_alert_message = 'VirusTotal 监控程序线程已退出。'
        send_alert_to_dingtalk(dingtalk_webhook, exit_alert_message)
        print(exit_alert_message)

def main():
    config = read_config('config.ini')
    API_KEY = config.get('API', 'VirusTotalAPIKey')
    WBAPI = config.get('API', 'wbapi')
    DINGTALK_WEBHOOK = config.get('DingTalk', 'WebhookURL')
    sha256_mapping = get_config('config.ini')

    logging.getLogger().setLevel(logging.INFO)
    dingtalk = create_dingtalk_bot(DINGTALK_WEBHOOK)
    atexit.register(send_exit_message, dingtalk)

    thread1 = threading.Thread(target=monitor_virustotal, args=(sha256_mapping, API_KEY, DINGTALK_WEBHOOK))
    thread2 = threading.Thread(target=monitor_sha256, args=(sha256_mapping, dingtalk, WBAPI))

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

if __name__ == "__main__":
    main()
