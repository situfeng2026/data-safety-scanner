#!/bin/bash
# 数据安全检查工具 - 启动脚本
# 双击此脚本即可运行

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=================================================="
echo "  数据安全检查工具 v1.0"
echo "  正在启动..."
echo "=================================================="
echo ""
echo "支持的敏感信息类型："
echo "  • 身份证号   • 手机号     • 银行卡号"
echo "  • 电子邮箱   • 固定电话   • IP地址"
echo "  • API密钥    • 护照号     • 地址关键词"
echo ""
echo "操作功能："
echo "  • 查看匹配上下文         • 打开文件位置"
echo "  • 脱敏处理（替换为***）   • 删除文件（移入废纸篓）"
echo "  • 导出扫描报告（JSON/文本）"
echo ""

# 检测Python3
PYTHON=$(which python3)
if [ -z "$PYTHON" ]; then
    echo "❌ 错误：未找到 Python3，请先安装 Python"
    echo "   下载地址: https://www.python.org/downloads/"
    read -p "按回车键退出..."
    exit 1
fi

echo "✅ Python3: $($PYTHON --version)"
echo ""
echo "启动GUI界面..."
echo "选择目录后点击「开始扫描」即可"
echo ""
echo "首次使用建议：先扫描一个小的测试目录熟悉功能"
echo ""

$PYTHON "$DIR/DataSafetyScanner.py"

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ 程序异常退出 (exit code: $EXIT_CODE)"
    echo "   请尝试在终端中运行: python3 \"$DIR/DataSafetyScanner.py\""
    read -p "按回车键退出..."
fi
