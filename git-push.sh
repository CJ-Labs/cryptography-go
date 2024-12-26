#!/bin/bash

# 显示当前路径
echo "Current path: $(pwd)"
echo

# git add
echo "git add ."
git add .
echo

# 获取提交信息
echo "Enter commit message: "
read commit_message
git commit -m "$commit_message"
echo

# pull
echo "git pull origin main"
git pull origin main
echo

# push
echo "git push origin main"
git push origin main
echo

echo "Success!"
echo

# 暂停
read -p "Press Enter to continue..."