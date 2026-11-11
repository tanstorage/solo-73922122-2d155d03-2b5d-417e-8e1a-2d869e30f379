"""TUF 1.0.37 根信任轮换支持包。

模块划分：
* canonicaljson —— TUF 规定的 canonical JSON 编码；
* keys          —— Ed25519 密钥解析、keyid 计算与签名验证；
* root_verify   —— root 元数据结构校验与整链轮换验证；
* store         —— SQLite 受信根存储 + 文件锁并发控制 + 启动文件引导；
* settings      —— 环境变量配置。
"""
