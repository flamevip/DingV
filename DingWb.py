import requests
import time
import logging
from dingtalkchatbot.chatbot import DingtalkChatbot
import configparser
import atexit

def get_config():
    """读取配置文件并返回字典列表"""
    config = configparser.ConfigParser()
    config.read("sha256.ini")
    return list(config["sha256s"].items())

def create_dingtalk_bot():
    """创建并返回钉钉机器人实例"""
    webhook_url = "https://oapi.dingtalk.com/robot/send?access_token="
    return DingtalkChatbot(webhook_url)

def send_exit_message(dingtalk):
    """程序退出前发送告警消息"""
    message = "程序已经终止"
    dingtalk.send_text(msg=message, is_at_all=True)

def monitor_sha256(sha256_dict, dingtalk, threshold=51):
    """循环监控 SHA256 并在数据大小超过阈值时发送告警消息"""
    while True:
        try:
            for sha256, name in sha256_dict:
                url = f'https://api.threatbook.cn/v3/file/report/multiengines?apikey=&sha256={sha256}'
                response = requests.get(url)
                data_size = len(response.content)
                if data_size > threshold:
                    logging.warning(f"警告：{url} 返回的数据大小为 {data_size} 字节！")
                    message = f"警告：{name}({sha256}) 返回的数据大小为 {data_size} 字节！"
                    dingtalk.send_text(msg=message, is_at_all=True)
            time.sleep(3600)  # 每隔1小时循环监控一次
        except Exception as e:
            logging.error(f"发生异常: {e}")
            message = f"程序发生异常: {e}"
            dingtalk.send_text(msg=message, is_at_all=True)
            time.sleep(60)  # 如果发生异常，等待1分钟后重新尝试

def main():
    logging.getLogger().setLevel(logging.INFO)
    sha256_dict = get_config()
    dingtalk = create_dingtalk_bot()
    atexit.register(send_exit_message, dingtalk)
    monitor_sha256(sha256_dict, dingtalk)
