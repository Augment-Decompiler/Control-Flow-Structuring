#coding:utf-8
import os

try:
    os.unlink("log.txt")
except:
    None
os.system("run.bat")