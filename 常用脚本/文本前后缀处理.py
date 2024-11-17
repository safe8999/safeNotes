import os
from tqdm import tqdm  # 用于显示进度条

# 设置前缀和后缀
head = ""
tail = "/userxxxxx"

# 输入文件名
input_file = "xxx.txt"
# 临时文件
temp_file = "out.txt"

# 检查文件是否存在
if not os.path.exists(input_file):
    print(f"文件 {input_file} 不存在！请检查路径。")
    exit(1)

# 读取文件并处理内容
with open(input_file, "r", encoding="utf-8") as infile:
    lines = infile.readlines()

# 打开临时文件进行写入
with open(temp_file, "w", encoding="utf-8") as outfile:
    for line in tqdm(lines, desc="正在处理", unit="行"):
        line = line.strip()  # 去掉每行首尾空白字符
        outfile.write(f"{head}{line}{tail}\n")

# 将临时文件覆盖原文件
os.replace(temp_file, input_file)
print("处理完成！")