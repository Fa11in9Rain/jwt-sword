# JWT-Sword

一个用于 JWT（JSON Web Token）安全测试的 Python 工具，支持多种常见攻击手法，帮助安全研究人员和开发者评估 JWT 实现的安全性。

## 功能特性

- **解析 JWT**：解码 Header、Payload 和签名部分，直观展示。
- **None 算法攻击**：允许修改 Header 或 Payload，生成无签名的 JWT。
- **HS256 算法攻击**：

  - 置空密钥攻击
  - 密钥字典爆破
  - 修改算法为 None
  - 导入密钥文件并重新签名
  - 爆破成功后支持修改 Payload
- **RS256 算法攻击**：

  - 导入私钥，使用 RS256 重新签名（支持修改 Payload）
  - 密钥混淆攻击：将算法改为 HS256，使用公钥作为 HMAC 密钥签名（支持修改 Payload）
- **交互式 Payload 修改**：支持修改多个字段，自动识别并转换类型（整数、布尔、浮点数等）。

## 安装

### 环境要求

- Python 3.6+
- 依赖库：`pyjwt`

### 安装步骤

1. 克隆仓库：

   ```
   git clone https://github.com/Fa11in9Rain/jwt-sword.git
   cd jwt-sword
   ```
2. 安装依赖：

   ```
   pip install pyjwt
   ```
3. 运行工具：

   ```
   python jwt-sword.py -j <JWT>
   ```

## 使用示例

```
python jwt-sword.py -j "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

输出 Header 和 Payload 的 JSON 格式，并显示算法。

## 支持功能

### 密钥置空攻击

### 加密算法设置none攻击

### 暴力破解弱密钥

### 私钥攻击

### RS256 密钥混淆攻击

## 注意事项

- 该工具仅用于授权安全测试，请勿用于非法用途。
- 爆破密钥时，字典文件应为每行一个候选密钥的文本文件。
- RS256 密钥文件需为 PEM 格式（如 `-----BEGIN PRIVATE KEY-----` 或 `-----BEGIN PUBLIC KEY-----`）。
- 如果遇到 `ImportError: No module named jwt`，请安装 PyJWT：`pip install pyjwt`。

## 贡献

欢迎提交 Issue 和 Pull Request。如果您有新的攻击方式或改进建议，请随时联系。

## 许可证

MIT License

---

**免责声明**：使用本工具所产生的任何后果由使用者自行承担，作者不承担任何责任。
