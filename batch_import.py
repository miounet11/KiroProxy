#!/usr/bin/env python3
"""批量导入 Kiro Token 脚本

使用方法:
1. 将 accessToken 列表保存到 tokens.txt（每行一个）
2. 运行: python batch_import.py tokens.txt
3. 或直接粘贴: python batch_import.py --paste
"""
import sys
import json
import uuid
import asyncio
import httpx
from pathlib import Path

PROXY_URL = "http://localhost:8080"

async def import_token(access_token: str, name: str) -> dict:
    """导入单个 token"""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{PROXY_URL}/api/accounts/manual",
            json={
                "access_token": access_token.strip(),
                "name": name
            }
        )
        return resp.json()

async def batch_import(tokens: list[str]):
    """批量导入"""
    print(f"准备导入 {len(tokens)} 个账号...")

    success = 0
    failed = 0

    for i, token in enumerate(tokens, 1):
        token = token.strip()
        if not token or len(token) < 50:  # 跳过空行和无效token
            continue

        name = f"批量导入-{i:03d}"
        try:
            result = await import_token(token, name)
            if result.get("ok"):
                print(f"✅ [{i}/{len(tokens)}] {name} 导入成功")
                success += 1
            else:
                print(f"❌ [{i}/{len(tokens)}] {name} 失败: {result.get('detail', '未知错误')}")
                failed += 1
        except Exception as e:
            print(f"❌ [{i}/{len(tokens)}] {name} 异常: {e}")
            failed += 1

        # 每10个暂停一下
        if i % 10 == 0:
            await asyncio.sleep(0.5)

    print(f"\n导入完成: 成功 {success}, 失败 {failed}")

def main():
    if len(sys.argv) < 2:
        print("使用方法:")
        print("  python batch_import.py tokens.txt")
        print("  python batch_import.py --paste")
        sys.exit(1)

    if sys.argv[1] == "--paste":
        print("请粘贴 Token 列表（每行一个），输入空行结束:")
        tokens = []
        while True:
            try:
                line = input()
                if not line:
                    break
                tokens.append(line)
            except EOFError:
                break
    else:
        file_path = Path(sys.argv[1])
        if not file_path.exists():
            print(f"文件不存在: {file_path}")
            sys.exit(1)
        tokens = file_path.read_text().strip().split("\n")

    tokens = [t for t in tokens if t.strip()]
    if not tokens:
        print("没有有效的 Token")
        sys.exit(1)

    asyncio.run(batch_import(tokens))

if __name__ == "__main__":
    main()
