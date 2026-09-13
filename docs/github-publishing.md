# GitHub 发布检查

这份目录已由原项目的白名单导出器生成。上传前仍需人工检查全部文件、许可证和凭据。

在导出目录独立验证：

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
python -m pip wheel . --no-deps -w dist
```

之后由维护者创建空 GitHub 仓库（建议先设为 Private）并使用 GitHub 给出的仓库地址：

```bash
git init -b main
git add .
git diff --cached --stat
git diff --cached
git commit -m "Prepare portable Monitor 3.0 source release"
# 将下方占位符换成你自己创建的仓库地址；不要把访问令牌嵌入地址。
git remote add origin <YOUR_GITHUB_REPOSITORY_URL>
git push -u origin main
```

发布前清单：

- [ ] 确认自己有权公开全部代码、依赖和示例；核对现有 Apache-2.0 许可归属。
- [ ] 检查是否有密码、Webhook、私钥、令牌、真实人员、设备清单和日志。
- [ ] 核查历史提交；`.gitignore` 不会清除已经提交的敏感信息。
- [ ] 填写真实维护者联系方式并配置私密漏洞反馈渠道；不要让用户公开上传敏感日志。
- [ ] 在自己的 GitHub 仓库执行 CI；本地通过不等于 GitHub Actions 已运行成功。
- [ ] 先在测试环境按安装文档部署。版本标签产物仍需扫描，不能上传现场离线包。

此项目准备过程不会创建仓库、推送代码或替你选择仓库公开范围。
