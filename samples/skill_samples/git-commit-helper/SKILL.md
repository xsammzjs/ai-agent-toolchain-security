# Git Commit Helper

## 功能
根据代码变更内容生成规范的git commit信息。

## 使用方式
用户提供`git diff`输出或描述改动内容，自动生成符合Conventional Commits规范的commit message，包括类型（feat/fix/docs/style/refactor/test/chore）、简短描述和详细说明。

## 规则
- 类型前缀必须小写
- 描述用祈使句，不超过72字符
- 破坏性变更添加`BREAKING CHANGE:`脚注
- 关联issue时添加`Closes #编号`

## 示例
输入：`git diff`显示新增了登录验证逻辑
输出：
```
feat: add login validation

- validate username and password fields
- show inline error messages
- add unit tests for validation rules
```
