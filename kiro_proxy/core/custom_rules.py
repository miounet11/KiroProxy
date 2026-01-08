"""自定义限速/异常规则管理器

借鉴 Tokens 平台的自定义规则功能：
- 支持关键字匹配
- 支持自定义限速时间
- 支持异常标记
"""
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from enum import Enum


class RuleAction(Enum):
    """规则动作"""
    LIMIT = "limit"      # 限速
    DEACTIVE = "deactive"  # 标记异常


@dataclass
class CustomRule:
    """自定义规则

    格式：
    - 限速: 关键字|LIMIT|时间 (例如: rate limit|LIMIT|1h)
    - 异常: 关键字|DEACTIVE (例如: account suspended|DEACTIVE)
    """
    keyword: str
    action: RuleAction
    duration_seconds: int = 3600  # 默认 1 小时


@dataclass
class RuleMatchResult:
    """规则匹配结果"""
    matched: bool
    rule: Optional[CustomRule] = None
    action: Optional[RuleAction] = None
    duration_seconds: int = 0


class CustomRuleManager:
    """自定义规则管理器"""

    def __init__(self):
        self.rules: List[CustomRule] = []
        self._load_default_rules()

    def _load_default_rules(self):
        """加载默认规则"""
        default_rules = [
            # 限速规则
            "rate limit|LIMIT|1h",
            "too many requests|LIMIT|30m",
            "throttl|LIMIT|30m",
            "quota exceeded|LIMIT|1h",
            "Resource has been exhausted|LIMIT|24h",
            "TEMPORARILY_SUSPENDED|LIMIT|24h",

            # 异常规则
            "account suspended|DEACTIVE",
            "account disabled|DEACTIVE",
            "invalid token|DEACTIVE",
            "unauthorized|DEACTIVE",
            "access denied|DEACTIVE",
        ]
        for rule_str in default_rules:
            self.add_rule_from_string(rule_str)

    def _parse_duration(self, duration_str: str) -> int:
        """解析时间字符串为秒数

        支持格式: 30s, 5m, 1h, 1d
        """
        duration_str = duration_str.strip().lower()
        if not duration_str:
            return 3600

        match = re.match(r'^(\d+)([smhd]?)$', duration_str)
        if not match:
            return 3600

        value = int(match.group(1))
        unit = match.group(2) or 's'

        multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
        return value * multipliers.get(unit, 1)

    def add_rule_from_string(self, rule_str: str) -> bool:
        """从字符串添加规则

        格式：
        - 关键字|LIMIT|时间
        - 关键字|DEACTIVE
        """
        parts = rule_str.strip().split("|")
        if len(parts) < 2:
            return False

        keyword = parts[0].strip().lower()
        action_str = parts[1].strip().upper()

        if action_str == "LIMIT":
            duration = self._parse_duration(parts[2]) if len(parts) > 2 else 3600
            self.rules.append(CustomRule(
                keyword=keyword,
                action=RuleAction.LIMIT,
                duration_seconds=duration
            ))
        elif action_str == "DEACTIVE":
            self.rules.append(CustomRule(
                keyword=keyword,
                action=RuleAction.DEACTIVE,
                duration_seconds=0
            ))
        else:
            return False

        return True

    def clear_rules(self):
        """清空所有规则"""
        self.rules = []

    def set_rules_from_text(self, text: str):
        """从多行文本设置规则"""
        self.clear_rules()
        self._load_default_rules()

        for line in text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                self.add_rule_from_string(line)

    def match(self, error_text: str) -> RuleMatchResult:
        """匹配错误文本"""
        error_lower = error_text.lower()

        for rule in self.rules:
            if rule.keyword in error_lower:
                return RuleMatchResult(
                    matched=True,
                    rule=rule,
                    action=rule.action,
                    duration_seconds=rule.duration_seconds
                )

        return RuleMatchResult(matched=False)

    def get_rules_text(self) -> str:
        """获取规则文本"""
        lines = []
        for rule in self.rules:
            if rule.action == RuleAction.LIMIT:
                # 转换秒数为可读格式
                if rule.duration_seconds >= 86400:
                    duration = f"{rule.duration_seconds // 86400}d"
                elif rule.duration_seconds >= 3600:
                    duration = f"{rule.duration_seconds // 3600}h"
                elif rule.duration_seconds >= 60:
                    duration = f"{rule.duration_seconds // 60}m"
                else:
                    duration = f"{rule.duration_seconds}s"
                lines.append(f"{rule.keyword}|LIMIT|{duration}")
            else:
                lines.append(f"{rule.keyword}|DEACTIVE")
        return "\n".join(lines)

    def get_stats(self) -> dict:
        """获取统计信息"""
        limit_rules = [r for r in self.rules if r.action == RuleAction.LIMIT]
        deactive_rules = [r for r in self.rules if r.action == RuleAction.DEACTIVE]
        return {
            "total_rules": len(self.rules),
            "limit_rules": len(limit_rules),
            "deactive_rules": len(deactive_rules),
        }


# 全局实例
rule_manager = CustomRuleManager()


def get_rule_manager() -> CustomRuleManager:
    """获取规则管理器实例"""
    return rule_manager
