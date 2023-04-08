import requests
import time
import logging
from dingtalkchatbot.chatbot import DingtalkChatbot
import configparser
import atexit

# 获取配置文件中的参数
config = configparser.ConfigParser()
config.read("sha256.ini")
sha256_list = list(config["sha256s"].values())

# 设置日志级别为INFO
logging.getLogger().setLevel(logging.INFO)

# 配置钉钉机器人 Webhook 地址
webhook_url = "https://oapi.dingtalk.com/robot/send?access_token="

# 创建钉钉机器人实例
dingtalk = DingtalkChatbot(webhook_url)
threshold = 51

def send_exit_message():
    """程序退出前发送告警消息"""
    message = "程序已经终止"
    dingtalk.send_text(msg=message, is_at_all=True)

atexit.register(send_exit_message)

while True:
    try:
        for sha256 in sha256_list:
            url = f'https://api.threatbook.cn/v3/file/report/multiengines?apikey=&sha256={sha256}'
            response = requests.get(url)
            data_size = len(response.content)
            if data_size > threshold:
                # 发送告警消息到钉钉群中
                logging.warning(f"警告：{url} 返回的数据大小为 {data_size} 字节！")
                message = f"警告：{sha256} 返回的数据大小为 {data_size} 字节！"
                dingtalk.send_text(msg=message, is_at_all=True)
        time.sleep(3600)  # 每隔1小时循环监控一次
    except Exception as e:
