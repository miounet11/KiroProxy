"""代理管理器 - 支持会话固定 IP

借鉴 Tokens 平台的代理会话固定功能：
- 通过 %s 占位符为每个 Token 生成唯一会话 ID
- 确保同一 Token 始终使用同一 IP
- 大幅降低封号风险
"""
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class ProxyConfig:
    """代理配置"""
    # 全局代理地址，支持 %s 占位符
    # 格式: http://user:pass@proxy.com:7890 或 http://user:pass@proxy.com:7890?session=%s
    proxy_url: str = ""

    # 是否启用代理
    enabled: bool = False


class ProxyManager:
    """代理管理器"""

    def __init__(self, config: ProxyConfig = None):
        self.config = config or ProxyConfig()
        self._session_cache: Dict[str, str] = {}

    def _generate_session_id(self, account_id: str) -> str:
        """为账号生成唯一会话 ID"""
        if account_id in self._session_cache:
            return self._session_cache[account_id]

        # 使用 MD5 生成固定的会话 ID
        session_id = hashlib.md5(f"kiro-{account_id}".encode()).hexdigest()[:16]
        self._session_cache[account_id] = session_id
        return session_id

    def get_proxy_for_account(self, account_id: str) -> Optional[str]:
        """获取账号对应的代理地址

        如果代理 URL 包含 %s 占位符，会替换为账号的唯一会话 ID
        这样可以确保同一账号始终使用同一 IP
        """
        if not self.config.enabled or not self.config.proxy_url:
            return None

        proxy_url = self.config.proxy_url.strip()

        # 如果包含 %s 占位符，替换为会话 ID
        if "%s" in proxy_url:
            session_id = self._generate_session_id(account_id)
            proxy_url = proxy_url.replace("%s", session_id)

        return proxy_url

    def get_httpx_proxies(self, account_id: str) -> Optional[Dict[str, str]]:
        """获取 httpx 格式的代理配置"""
        proxy = self.get_proxy_for_account(account_id)
        if not proxy:
            return None

        return {
            "http://": proxy,
            "https://": proxy,
        }

    def update_config(self, **kwargs):
        """更新配置"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            "enabled": self.config.enabled,
            "proxy_url": self.config.proxy_url[:50] + "..." if len(self.config.proxy_url) > 50 else self.config.proxy_url,
            "has_session_placeholder": "%s" in self.config.proxy_url if self.config.proxy_url else False,
            "cached_sessions": len(self._session_cache),
        }


# 全局实例
proxy_manager = ProxyManager()


def get_proxy_manager() -> ProxyManager:
    """获取代理管理器实例"""
    return proxy_manager
