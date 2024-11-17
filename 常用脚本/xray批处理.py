# -*- coding: utf-8 -*-
import os
import re
import subprocess
from queue import Queue
from threading import Thread
import argparse
import logging
from urllib.parse import urlparse

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_targets(input_file):
    """从文件中获取URL目标并返回队列"""
    queue = Queue()
    pattern = re.compile(r'^(https?://)')

    try:
        with open(input_file, "r", encoding='utf-8') as f:
            for line in f:
                target_url = line.strip()
                if not pattern.match(target_url):
                    target_url = "http://" + target_url  # 默认使用http
                queue.put(target_url)
    except Exception as e:
        logging.error("Failed to read targets from {}: {}".format(input_file, e))

    return queue

def extract_domain(url):
    """从给定的 URL 中提取域名"""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc  # 获取域名部分
    return domain

def do_scan(target_url, output_dir):
    """执行Xray扫描并保存输出"""
    # 提取域名作为输出文件名
    output_filename = extract_domain(target_url)

    # 确保文件名安全
    output_filename = re.sub(r'[<>:"/\\|?*]', '_', output_filename)  # 替换无效字符
    command = [
        "C:/tools/xray_windows_amd64/xray_windows_amd64.exe",  # Xray工具路径（需要修改的地方）
        "webscan",
        "--basic-crawler",
        target_url,
        "--html-output", os.path.join(output_dir, "{}.html".format(output_filename))  # 使用域名作为输出文件名
    ]

    try:
        logging.info("Scanning {}...".format(target_url))  # 打印当前正在扫描的URL
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            logging.error("Error scanning {}: {}".format(target_url, result.stderr))
    except Exception as e:
        logging.error("Exception while scanning {}: {}".format(target_url, e))

def worker(queue, output_dir):
    """线程工作函数，用于处理队列中的任务"""
    while True:
        target = queue.get()
        if target is None:  # 结束标志
            break
        do_scan(target, output_dir)
        queue.task_done()

def main(input_file, output_dir, threads):
    """主函数，设置多线程扫描"""
    queue = get_targets(input_file)

    # 启动工作线程
    thread_list = []
    for _ in range(threads):
        t = Thread(target=worker, args=(queue, output_dir))
        t.start()
        thread_list.append(t)

    queue.join()  # 等待任务完成

    # Notify threads to exit
    for _ in thread_list:
        queue.put(None)
    for t in thread_list:
        t.join()

    logging.info("Xray Scan Completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Xray Bulk Scanner")
    parser.add_argument("-i", "--input", required=True, help="目标URL文件，每行一个，例如：xray_url.txt")
    parser.add_argument("-o", "--output", required=True, help="扫描结果保存目录")
    parser.add_argument("-t", "--threads", type=int, default=10, help="并发线程数，默认10")
    args = parser.parse_args()

    if not os.path.exists(args.output):
        os.makedirs(args.output)

    main(args.input, args.output, args.threads)
